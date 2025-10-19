import mongoose from 'mongoose';
import { MongoMemoryServer } from "mongodb-memory-server";
import request from "supertest";
import app from "../app";
import userModel from "../models/userModel";
import jwt, {JsonWebTokenError} from "jsonwebtoken";
import bcrypt from "bcrypt";

jest.mock('../config/db', () => jest.fn());

const hashPassword = async (password) => await bcrypt.hash(password, 10);

describe('Integration between Auth Controller with database', () => {
  let mongodbServer;
  var userInDb;
  const userInDbUnhashedPassword = "mock_password";

  beforeAll(async() => {
    mongodbServer = await MongoMemoryServer.create();
    const uri = mongodbServer.getUri();
    await mongoose.connect(uri);
  });

  afterAll(async() => {
    await mongoose.disconnect();
    await mongodbServer.stop();
  });

  // Clean up collections before each test case so that every test case starts with an empty database
  beforeEach(async() => {
    const collections = await mongoose.connection.db.collections();

    for(let collection of collections) {
      await collection.deleteMany();
    }
    userInDb = {
      name: "mock_nname",
      email: "mock_email@gmail.com",
      password: await hashPassword(userInDbUnhashedPassword),
      phone: "mock_phone",
      address: "mock_address",
      answer: "mock_answer",
      role: 0
    };
    await userModel.create(userInDb);
  });

  describe("/register", () => {
    it('Register new user should return 201 with new user created in database', async() => {
      // Arrange
      const newUser = {
        name: "mock_new_name",
        email: "mock_new_email@gmail.com",
        password: "mock_new_password",
        phone: "mock_new_phone",
        address: "mock_new_address",
        answer: "mock_new_answer",
        role: 0
      };

      // Act
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(newUser).set('Accept', 'application/json');

      // Assert
      expect(res.statusCode).toBe(201);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'User Register Successfully');
      expect(res.body).toHaveProperty('user');

      const user = res.body.user;
      expect(user.name).toBe(newUser.name);
      expect(user.email).toBe(newUser.email);
      expect(user.phone).toBe(newUser.phone);
      expect(user.address).toBe(newUser.address);
      expect(user.password).not.toBe(newUser.password);
      expect(user.answer).toBe(newUser.answer);

      const userInDb = await userModel.findOne({ email: newUser.email });
      expect(userInDb).not.toBeNull();
      expect(userInDb.password).not.toBe(newUser.password);
      expect(userInDb.name).toBe(newUser.name);
      expect(userInDb.email).toBe(newUser.email);
      expect(userInDb.phone).toBe(newUser.phone);
      expect(userInDb.address).toBe(newUser.address);
      expect(userInDb.password).not.toBe(newUser.password);
      expect(userInDb.answer).toBe(newUser.answer);
    });

    it('Register new user should return 200 when user already exists in database and does not created duplicate user', async() => {
      // Arrange
      const existingUser = {
        name: "mock_new_name",
        email: "mock_new_email@gmail.com",
        password: "mock_new_password",
        phone: "mock_new_phone",
        address: "mock_new_address",
        answer: "mock_new_answer",
        role: 0
      };

      await userModel.create(existingUser);

      const newUser = {
        name: "mock_new_name",
        email: "mock_new_email@gmail.com",
        password: "mock_new_password",
        phone: "mock_new_phone",
        address: "mock_new_address",
        answer: "mock_new_answer",
        role: 0
      };

      // Act
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(newUser).set('Accept', 'application/json');

      // Assert
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('success', false);
      expect(res.body).toHaveProperty('message', 'Already Register please login');
      expect(res.body).not.toHaveProperty('user');

      const usersWithEmail = await userModel.find({ name: newUser.name, email: newUser.email });
      expect(usersWithEmail).toHaveLength(1);
    });

    it('Should return 500 if database save fails', async () => {
      jest.spyOn(userModel.prototype, 'save').mockImplementationOnce(() => {
        throw new Error('Mock DB error');
      });

      const newUser = {
        name: "mock_new_name",
        email: "mock_new_email@gmail.com",
        password: "mock_new_password",
        phone: "mock_new_phone",
        address: "mock_new_address",
        answer: "mock_new_answer"
      }

      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(newUser);

      expect(res.statusCode).toBe(500);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Error in Registration");
    });
  });

  describe("/login", () => {
    it("Should return 404 when email or password is missing", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({
          email: userInDb.email,
        });

      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Invalid email or password");
    });

    it("Should return 404 when email is not registered", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({
          email: "unknown_email@gmail.com",
          password: userInDb.password,
        });

      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Email is not registered");
    });

    it("Should return 401 when password is invalid", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({
          email: userInDb.email,
          password: "invalid_password",
        });
      console.log(res.body.message);

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Invalid Password");
    });

    it("Should return 200 and JWT token when login is successful", async () => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: userInDb.email, password: userInDbUnhashedPassword })
        .set("Accept", "application/json");

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe("login successfully");
      expect(res.body).toHaveProperty("token");

      const resUser = res.body.user;
      expect(resUser).toHaveProperty("_id");
      expect(resUser).not.toHaveProperty("password");
      expect(resUser.email).toBe(userInDb.email);
      expect(resUser.name).toBe(userInDb.name);
      expect(resUser.phone).toBe(userInDb.phone);
      expect(resUser.address).toBe(userInDb.address);
      expect(resUser.role).toBe(0);
    });

    it("Should return 500 if database query throws an error", async () => {
      jest
        .spyOn(userModel, "findOne")
        .mockImplementationOnce(() => {
          throw new Error("Mock DB error");
        });

      const res = await request(app)
        .post("/api/v1/auth/login")
        .send({ email: "mock_email@gmail.com", password: "mock_password" });

      expect(res.statusCode).toBe(500);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Error in login");

      jest.restoreAllMocks();
    });
  });

  describe("/forgot-password", () => {
    it("Should return 400 if email is missing", async () => {
      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({ answer: "mock_answer", newPassword: "new_password" });

      expect(res.statusCode).toBe(400);
      expect(res.body.message).toBe("Email is required");
    });

    it("Should return 400 if answer is missing", async () => {
      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({ email: userInDb.email, newPassword: "new_password" });

      expect(res.statusCode).toBe(400);
      expect(res.body.message).toBe("Answer is required");
    });

    it("Should return 400 if newPassword is missing", async () => {
      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({ email: userInDb.email, answer: "mock_answer" });

      expect(res.statusCode).toBe(400);
      expect(res.body.message).toBe("New Password is required");
    });

    it("Should return 404 when email or answer is incorrect", async () => {
      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({
          email: "wrong_email@gmail.com",
          answer: "wrong_answer",
          newPassword: "new_password",
        });

      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Wrong Email Or Answer");
    });

    it("Should return 200 and update password successfully", async () => {
      const newPassword = "new_password";

      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({
          email: userInDb.email,
          answer: userInDb.answer,
          newPassword,
        })
        .set("Accept", "application/json");

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe("Password Reset Successfully");

      const updatedUser = await userModel.findOne({ email: userInDb.email });
      expect(updatedUser).not.toBeNull();
      const isPasswordChanged = await bcrypt.compare(
        newPassword,
        updatedUser.password
      );
      expect(isPasswordChanged).toBe(true);
    });

    it("Should return 500 if database query throws error", async () => {
      jest
        .spyOn(userModel, "findOne")
        .mockImplementationOnce(() => {
          throw new Error("Mock DB error");
        });

      const res = await request(app)
        .post("/api/v1/auth/forgot-password")
        .send({
          email: userInDb.email,
          answer: userInDb.answer,
          newPassword: "new_password",
        });

      expect(res.statusCode).toBe(500);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Something went wrong");

      jest.restoreAllMocks();
    });
  });
  describe("/test (Protected Admin Route)", () => {
    let adminUser;
    let normalUser;
    const JWT_SECRET = process.env.JWT_SECRET || "mockKey";

    beforeEach(async () => {
      // Create one admin and one normal user
      adminUser = await userModel.create({
        name: "Admin User",
        email: "admin@gmail.com",
        password: await bcrypt.hash("admin123", 10),
        phone: "12345678",
        address: "Admin Street",
        answer: "mock_answer",
        role: 1,
      });

      normalUser = await userModel.create({
        name: "Normal User",
        email: "user@gmail.com",
        password: await bcrypt.hash("user123", 10),
        phone: "12345678",
        address: "User Street",
        answer: "mock_answer",
        role: 0,
      });
    });

    it("Should return 401 when no token is provided", async () => {
      const res = await request(app).get("/api/v1/auth/test");
      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Unauthorized: Invalid or missing token");
    });

    it("Should return 401 and 'UnAuthorized Access' when user is not admin", async () => {
      const userToken = jwt.sign({ _id: normalUser._id }, JWT_SECRET, {
        expiresIn: "7d",
      });

      const res = await request(app)
        .get("/api/v1/auth/test")
        .set("Authorization", userToken);

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("UnAuthorized Access");
    });

    it("Should return 200 and 'Protected Routes' when admin accesses", async () => {
      const adminToken = jwt.sign({ _id: adminUser._id }, JWT_SECRET, {
        expiresIn: "7d",
      });

      const res = await request(app)
        .get("/api/v1/auth/test")
        .set("Authorization", adminToken)
        .set("Accept", "application/json");

      expect(res.statusCode).toBe(200);
      expect(res.text).toBe("Protected Routes");
    });

    it("Should return 401 and 'Error in admin middleware' if DB lookup fails", async () => {
      jest
        .spyOn(userModel, "findById")
        .mockImplementationOnce(() => {
          throw new Error("Mock DB error");
        });

      const adminToken = jwt.sign({ _id: adminUser._id }, JWT_SECRET, {
        expiresIn: "7d",
      });

      const res = await request(app)
        .get("/api/v1/auth/test")
        .set("Authorization", adminToken);

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Error in admin middleware");

      jest.restoreAllMocks();
    });
  });
});