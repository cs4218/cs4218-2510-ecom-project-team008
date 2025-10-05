import JWT from "jsonwebtoken";
import userModel from "../models/userModel.js";
import {
  registerController, loginController, forgotPasswordController, testController,
  updateProfileController, getOrdersController, getAllOrdersController,
  orderStatusController, getAllUsersController
} from "./authController.js";
import { comparePassword, hashPassword } from "../helpers/authHelper.js";
import orderModel from "../models/orderModel";

jest.mock("../models/userModel.js");
jest.mock("./../helpers/authHelper.js");
jest.mock("jsonwebtoken");

const mockName = "mockName";
const mockEmail = "mockEmail";
const mockPassword = "mockPassword";
const mockPhone = "mockPhone";
const mockAddress = "mockAddress";
const mockAnswer = "mockAnswer";
const mockRequest = {
  body: {
    name: mockName,
    email: mockEmail,
    password: mockPassword,
    phone: mockPhone,
    address: mockAddress,
    answer: mockAnswer,
  },
};

describe('registerController', () => {
  let res;

  beforeEach(() => {
    res = {
      send: jest.fn(),
      status: jest.fn().mockReturnThis(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const invalidInputs = [
    { field: 'name', value: '', expectedMessage: 'Name is Required' },
    { field: 'email', value: '', expectedMessage: 'Email is Required' },
    { field: 'password', value: '', expectedMessage: 'Password is Required' },
    { field: 'password', value: 'abcd', expectedMessage: 'Password must be at least 6 characters' },
    { field: 'password', value: 'abcde', expectedMessage: 'Password must be at least 6 characters' },
    { field: 'phone', value: '', expectedMessage: 'Phone number is Required' },
    { field: 'address', value: '', expectedMessage: 'Address is Required' },
    { field: 'answer', value: '', expectedMessage: 'Answer is Required' },
  ]

  test.each(invalidInputs)(
    'should return 400 $field is required error when there is no attribute $field in request body',
    async ({ field, value, expectedMessage }) => {
      // Arrange
      const req = { body: { ...mockRequest.body, [field]: value } };
      
      // Act
      await registerController(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.send).toHaveBeenCalledWith({ message: expectedMessage });
    }
  );

  const validPasswords = [
    { value: "abcdef" },
    { value: "abcdefg" },
  ];

  test.each(validPasswords)(
    'should register successfully when password length >= 6',
    async ({ value }) => {
      const req = { body: { ...mockRequest.body, password: value } };

      await registerController(req, res);

      expect(userModel.findOne).toHaveBeenCalledWith({ email: mockEmail });
      expect(hashPassword).toHaveBeenCalledWith(value);
      expect(userModel.prototype.save).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
    }
  );

  test('should return 200 registration success when user with given email is found', async () => {
    // Arrange
    const req = mockRequest;
    userModel.findOne = jest.fn().mockImplementation(async ({ email }) => mockRequest);

    // Act
    await registerController(req, res);

    // Assert
    expect(userModel.findOne).toHaveBeenCalledWith({ 
      email: mockEmail
    });
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({ success: false, message: 'Already Register please login' })
  });

  test("should return 201 registration success when user with given email is not found", async () => {
    // Arrange
    const req = mockRequest;
    const mockUserCreated = {
      _id: "mock_id",
      name: mockName,
      email: mockEmail,
      phone: mockPhone,
      address: mockAddress,
      password: "mockHashedPassword",
      answer: mockAnswer,
    };
    userModel.findOne.mockResolvedValue(null);
    hashPassword.mockResolvedValue("mockHashedPassword");
    userModel.prototype.save = jest.fn().mockResolvedValue(mockUserCreated);

    // Act
    await registerController(req, res);

    // Assert
    expect(userModel.findOne).toHaveBeenCalledWith({
      email: mockEmail
    });
    expect(hashPassword).toHaveBeenCalledWith(mockPassword);
    expect(userModel.prototype.save).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.send).toHaveBeenCalledWith({
      success: true,
      message: "User Register Successfully",
      user: mockUserCreated,
    });
  });

  test('should return 500 registration error when error is thrown while saving user model', async () => {
    // Arrange
    const req = mockRequest;
    const expectedError = new Error("Internal server error")
    userModel.findOne.mockResolvedValue(null);
    hashPassword.mockResolvedValue("mockHashedPassword");
    userModel.prototype.save = jest.fn().mockRejectedValue(expectedError);

    // Act
    await registerController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error in Registration",
      error: expectedError,
    });
  });

  test('should return 500 registration error when error is thrown while finding existing user', async () => {
    // Arrange
    const req = mockRequest;
    const expectedError = new Error("Internal server error")
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    userModel.findOne.mockRejectedValue(expectedError);

    // Act
    await registerController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error in Registration",
      error: expectedError,
    });
    expect(consoleSpy).toHaveBeenCalledWith(expect.any(Error));

    consoleSpy.mockRestore();
  });
});

describe('loginController', () => {
  let res;

    beforeEach(() => {
      res = {
        send: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    const invalidInputs = [
      { field: 'email', value: '' },
      { field: 'password', value: '' },
    ]

  test.each(invalidInputs)(
    'should return 404 with invalid email or password when $field is missing',
    async ({ field, value }) => {
      // Arrange
      const req = { body: { ...mockRequest.body, [field]: value } };

      // Act
      await loginController(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.send).toHaveBeenCalledWith({
        success: false,
        message: "Invalid email or password",
      });
    }
  );

  test('should return 404 with email not registered error message', async () => {
    // Arrange
    const req = mockRequest;
    userModel.findOne.mockResolvedValue(null);

    // Act
    await loginController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ success: false, message: 'Email is not registered' });
  });

  test("should return 200 when request password is same as user's existing password", async () => {
    // Arrange
    const req = mockRequest;
    userModel.findOne.mockResolvedValue({ _id: 'mock_id', name: mockName, password: mockPassword, email: mockEmail, phone: mockPhone, address: mockAddress });
    comparePassword.mockResolvedValue(false);

    // Act
    await loginController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.send).toHaveBeenCalledWith({ success: false, message: 'Invalid Password' });
  });

  test('should return 200 when password provided matches and all required fields provided', async () => {
    // Arrange
    const req = mockRequest;
    const returnedUser = { _id: 'mock_id', name: mockName, password: mockPassword, email: mockEmail, phone: mockPhone, address: mockAddress, role: 'mock_role' };
    userModel.findOne.mockResolvedValue(returnedUser);
    comparePassword.mockResolvedValue(true);
    JWT.sign.mockResolvedValue('signed_token');

    // Act
    await loginController(req, res);

    // Assert
    const { password, ...expectedUserModel } = returnedUser;
    expect(JWT.sign).toHaveBeenCalledWith(
      { _id: 'mock_id' },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({
      success: true,
      message: 'login successfully',
      user: expectedUserModel, // exclude password
      token: 'signed_token'
    })
  });

  test('should return 500 when exception is thrown while finding existing user', async () => {
    // Arrange
    const req = mockRequest;
    const errorThrown = new Error("Internal server error");
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    userModel.findOne.mockRejectedValue(errorThrown);

    // Act
    await loginController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error in login",
      error: errorThrown,
    });
    expect(consoleSpy).toHaveBeenCalledWith(errorThrown);

    consoleSpy.mockRestore();
  });
});

describe('forgotPasswordController', () => {
  let res;

  beforeEach(() => {
    res = {
      send: jest.fn(),
      status: jest.fn().mockReturnThis(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

    const invalidInputs = [
    { field: 'email', value: '', expectedMessage: 'Email is required' },
    { field: 'answer', value: '', expectedMessage: 'Answer is required' },
    { field: 'newPassword', value: '', expectedMessage: 'New Password is required' },
  ]

  test.each(invalidInputs)(
    'should return 400 $field is required error when there is no attribute $field in request body',
    async ({ field, value, expectedMessage }) => {
      // Arrange
      const req = { body: { ...mockRequest.body, [field]: value } };
      
      // Act
      await forgotPasswordController(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.send).toHaveBeenCalledWith({ message: expectedMessage });
    }
  );

  test('should return 404 when unable to find user with given email and answer', async () => {
    // Arrange
    const req = mockRequest;
    userModel.findOne.mockResolvedValue(null);

    // Act
    await forgotPasswordController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith({ success: false, message: 'Wrong Email Or Answer' });
  });

  test('should return 200 and reset password successfully when user is found', async () => {
    // Arrange
    const req = mockRequest;
    const mockUser = { _id: "mock_id" };
    userModel.findOne.mockResolvedValue(mockUser);
    hashPassword.mockResolvedValue("hashedPassword");
    userModel.findByIdAndUpdate.mockResolvedValue({});

    // Act
    await forgotPasswordController(req, res);

    // Assert
    expect(hashPassword).toHaveBeenCalledWith(req.body.newPassword);
    expect(userModel.findByIdAndUpdate).toHaveBeenCalledWith(mockUser._id, { password: "hashedPassword" });
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({ success: true, message: "Password Reset Successfully" });
  });

  test('should return 500 when an error is thrown', async () => {
    // Arrange
    const req = mockRequest;
    const errorThrown = new Error("Internal Server Error");
    userModel.findOne.mockRejectedValue(errorThrown);
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

    // Act
    await forgotPasswordController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Something went wrong",
      error: errorThrown,
    });
    expect(consoleSpy).toHaveBeenCalledWith(errorThrown);

    consoleSpy.mockRestore();
  });
});

describe('testController', () => {
  let req, res;

  beforeEach(() => {
    res = {
      send: jest.fn(),
      status: jest.fn().mockReturnThis(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('should return respond with protected routes', async () => {
    // Arrange
    const req = mockRequest;

    // Act
    await testController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith('Protected Routes');
  });

  test('should log error if something goes wrong', () => {
    // Arrange
    const errorThrown = new Error("Internal Server Error");
    res.status = jest.fn((code) => {
      if (code === 200) {
        throw errorThrown;
      }
      return res;
    });
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

    // Act
    testController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({ error: errorThrown });
    expect(consoleSpy).toHaveBeenCalledWith(errorThrown);

    consoleSpy.mockRestore();
  });
})

describe('updateProfileController', () => {
  let res;

  beforeEach(() => {
    res = {
      send: jest.fn(),
      json: jest.fn(),
      status: jest.fn().mockReturnThis(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const validUserId = 1
  const invalidUserId = 2

  const mockProfileUpdateRequest = {
    user: {
      _id: validUserId
    },
    body: {
      name: "Updated User",
      password:"Updated Password",
      address:"Updated Address",
      phone: "Updated Phone"
    }
  }

  const mockUser = {
    _id: validUserId,
    name: "Mock Name",
    email:"Mock Email",
    password:"123456",
    address:"Mock Address",
    phone: "Mock Phone"
  }

  test('should return 200 when no user is found but input value is not empty', async() => {
    // Arrange
    const req = {
      ...mockProfileUpdateRequest,
      user: {_id: invalidUserId}
    }
    userModel.findById.mockResolvedValueOnce(null)
    userModel.findByIdAndUpdate.mockResolvedValueOnce(null)

    // Act
    await updateProfileController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({
      success: true,
      message: "Profile Updated Successfully",
      updatedUser: null
    })
  })

  test('should return 400 when no user is found and input value is empty', async() => {
    // Arrange
    const req = {
      user: {
        _id: invalidUserId
      },
      body: {}
    };
    userModel.findById.mockResolvedValueOnce(null);

    // Act
    await updateProfileController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error While Update profile",
      error: expect.any(TypeError)
    })
  })

  test('should return 400 when new password of less than length 6 is given', async () => {
    // Arrange
    const req = {
      ...mockProfileUpdateRequest,
      body: {
        ...mockProfileUpdateRequest.body,
        password: "12345"
      }
    }
    userModel.findById.mockResolvedValueOnce(mockUser)

    // Act
    await updateProfileController(req, res);

    // Assert
    expect(res.json).toHaveBeenCalledWith({ error: "Passsword is required and 6 character long" })
  });

  const validUpdateValues = [
    {field: "name", value: "Updated User"},
    {field: "password", value: "654321"},
    {field: "address", value: "Updated Address"},
    {field: "phone", value: "Updated Phone"},
  ]
  test.each(validUpdateValues)(
      "should return 200 and update user profile successfully if given valid value", async ({field, value}) => {
        // Arrange
        const req = {
          user: {_id: validUserId},
          body: {[field]: value}
        }
        userModel.findById.mockResolvedValueOnce(mockUser)
        const updatedUser = {
          ...mockUser,
          [field]: value
        }
        userModel.findByIdAndUpdate.mockResolvedValueOnce(updatedUser)

        // Act
        await updateProfileController(req, res);

        // Assert
        expect(res.status).toHaveBeenCalledWith(200)
        expect(res.send).toHaveBeenCalledWith({
          success: true,
          message: "Profile Updated Successfully",
          updatedUser
        })
      }
  )

  const emptyUpdateValues = [
    {field: "name", value: ""},
    {field: "password", value: ""},
    {field: "address", value: ""},
    {field: "phone", value: ""},
  ]
  test.each(emptyUpdateValues)(
      "should return 200 and preserve the old value if given empty or undefined value", async ({field, value}) => {
        // Arrange
        const req = {
          user: {_id: validUserId},
          body: {[field]: value}
        }
        userModel.findById.mockResolvedValueOnce(mockUser)
        userModel.findByIdAndUpdate.mockResolvedValue(mockUser)

        // Act
        await updateProfileController(req, res);

        // Assert
        expect(res.status).toHaveBeenCalledWith(200);
        expect(res.send).toHaveBeenCalledWith({
          success: true,
          message: "Profile Updated Successfully",
          updatedUser: mockUser
        })
      }
  );

  it('should return 500 and console log error if error is thrown', async () => {
    // Arrange
    const req = {
      user: {_id: validUserId},
      body: {name: "Updated Name"}
    };
    const error = new Error("An Error Occurred...");
    userModel.findById.mockResolvedValueOnce(mockUser);
    userModel.findByIdAndUpdate.mockRejectedValueOnce(error);
    const consoleSpy = jest.spyOn(console, 'log');

    // Act
    await updateProfileController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error While Update profile",
      error,
    });
    expect(consoleSpy).toHaveBeenCalledWith(error);
  });
});

jest.mock("../models/orderModel");
describe('getOrdersController', () => {
  let res;
  const mockProduct = {
    name: "Mock Name",
    slug: "Mock Slug",
    description: "Mock Description",
    price: 19.99,
    category: "Mock Category",
    quantity: 1,
    shipping: true,
  };
  const mockOrder = {
    products: [1],
    payment: {success: true, message: "Mock Message"},
    buyer: {_id: 1},
    status: "Not Process"
  };

  beforeEach(() => {
    res = {
      send: jest.fn(),
      json: jest.fn(),
      status: jest.fn().mockReturnThis(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('should return the orders if found', async() => {
    // Arrange
    const req = { user: { _id: 1 } };
    const mockPopulatedOrders = [{
      ...mockOrder,
      products: [mockProduct],
      buyer: "Mock Name",
    }];
    orderModel.find.mockReturnValueOnce({
      populate: jest.fn().mockReturnValueOnce({
        populate: jest.fn().mockReturnValueOnce(mockPopulatedOrders)
      })
    });

    // Act
    await getOrdersController(req, res);

    // Assert
    expect(res.json).toHaveBeenCalledWith(mockPopulatedOrders);
  });

  test('should return 500 when error is thrown', async() => {
    // Arrange
    const req = {user: {_id: 1}};
    const error = new Error("An Error Occur")
    orderModel.find.mockReturnValueOnce({
      populate: jest.fn().mockReturnValueOnce({
        populate: jest.fn(() => {
          throw error;
        })
      })
    });

    // Act
    await getOrdersController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error While Getting Orders",
      error,
    });
  });
});

describe('getAllOrdersController', () => {
  let res;
  beforeEach(() => {
    res = {
      json: jest.fn(),
      send: jest.fn(),
      status: jest.fn().mockReturnThis()
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const mockProduct1 = {
    name: "Mock Name",
    slug: "Mock Slug",
    description: "Mock Description",
    price: 19.99,
    category: "Mock Category",
    quantity: 1,
    shipping: true,
  };
  const mockProduct2 = {
    name: "Mock Name2",
    slug: "Mock Slug2",
    description: "Mock Description2",
    price: 29.99,
    category: "Mock Category2",
    quantity: 2,
    shipping: false,
  };
  const mockProduct3 = {
    name: "Mock Name3",
    slug: "Mock Slug3",
    description: "Mock Description3",
    price: 39.99,
    category: "Mock Category3",
    quantity: 3,
    shipping: true,
  };
  const mockOrder1 = {
    products: [mockProduct1],
    payment: {success: true, message: "Mock Message"},
    buyer: {_id: 1},
    status: "Not Process"
  };
  const mockOrder2 = {
    products: [mockProduct1, mockProduct2],
    payment: {success: false, message: "Mock Message2"},
    buyer: {_id: 2},
    status: "Processing"
  };
  const mockOrder3 = {
    products: [mockProduct1, mockProduct2, mockProduct3],
    payment: {success: true, message: "Mock Message3"},
    buyer: {_id: 3},
    status: "Shipped"
  };

  test('should return all orders when found', async () => {
    // Arrange
    const req = {};
    const mockResults = [mockOrder1, mockOrder2, mockOrder3];

    orderModel.find.mockReturnValueOnce({
      populate: jest.fn().mockReturnValueOnce({
        populate: jest.fn().mockReturnValueOnce({
          sort: jest.fn().mockResolvedValueOnce(mockResults)
        })
      })
    })

    // Act
    await getAllOrdersController(req, res);

    // Assert
    expect(res.json).toHaveBeenCalledWith(mockResults);
  })

  test('should return 500 and console log error when error is thrown', async () => {
    // Arrange
    const req = {};
    const error = new Error("An error occurred...")
    orderModel.find.mockReturnValueOnce({
      populate: jest.fn().mockReturnValueOnce({
        populate: jest.fn().mockReturnValueOnce({
          sort: jest.fn().mockRejectedValueOnce(error)
        })
      })
    });
    const consoleSpy = jest.spyOn(console, 'log');
    consoleSpy.mockImplementationOnce(() => {});

    // Act
    await getAllOrdersController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error While Getting Orders",
      error,
    });
    expect(consoleSpy).toHaveBeenCalledWith(error);
  });
});

describe('orderStatusController', () => {
  let res;
  let mockProduct, mockOrder;
  beforeEach(() => {
    res = {
      json: jest.fn(),
      send: jest.fn(),
      status: jest.fn().mockReturnThis()
    };

    mockProduct = {
      name: "Mock Name",
      slug: "Mock Slug",
      description: "Mock Description",
      price: 19.99,
      category: "Mock Category",
      quantity: 1,
      shipping: true,
    };

    mockOrder = {
      _id: 1,
      products: [1],
      payment: {success: true, message: "Mock Message"},
      buyer: {_id: 1},
      status: "Not Process"
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const statuses = ["Not Process", "Processing", "Shipped", "delivered", "cancel"]
  test.each(statuses)(
      'should update order to each valid state properly', async (status) => {
        // Arrange
        const req = {
          params: {orderId: mockOrder._id},
          body: {status: status}
        }
        const updatedOrder = {
          ...mockOrder,
          status: status
        };
        orderModel.findByIdAndUpdate.mockResolvedValueOnce(updatedOrder);

        // Act
        await orderStatusController(req, res);

        // Assert
        expect(res.json).toHaveBeenCalledWith(updatedOrder);
  });

  test.each(statuses)(
      'should return null if no order with given id is found', async(status) => {
        // Arrange
        const req = {
          params: {orderId: "Invalid ID"},
          body: {status: status}
        };
        orderModel.findByIdAndUpdate.mockResolvedValueOnce(null);

        // Act
        await orderStatusController(req, res);

        // Assert
        expect(res.json).toHaveBeenCalledWith(null);
  });

  test.each(statuses)(
      'should return 500 with error message when error occurs', async(status) => {
        // Arrange
        const req = {
          params: {orderId: mockOrder._id},
          body: {status: status}
        };
        const error = new Error("An error occurred...");
        orderModel.findByIdAndUpdate.mockRejectedValueOnce(error);
        const consoleSpy = jest.spyOn(console, 'log');

        // Act
        await orderStatusController(req, res);

        // Assert
        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.send).toHaveBeenCalledWith({
          success: false,
          message: "Error While Updating Order",
          error,
        });
        expect(consoleSpy).toHaveBeenCalledWith(error);
      }
  )
});

describe('getAllUsersController', () => {
  let res;
  const mockUser = {
    _id: 1,
    name: "Mock Name",
    email: "Mock Email",
    phone: "Mock Phone",
    address: "Mock Address"
  };

  beforeEach(() => {
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      send: jest.fn(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should return users json when find successful', async() => {
    // Arrange
    const req = {};
    const mockResults = [mockUser];
    userModel.find.mockReturnValueOnce({
      sort: jest.fn().mockReturnValueOnce(mockResults)
    });

    // Act
    await getAllUsersController(req, res);

    // Assert
    expect(res.json).toHaveBeenCalledWith(mockResults);
  });

  it('should return 500 and console log error if any error occurs', async() => {
    // Arrange
    const req = {};
    const error = new Error("An Error Occurred...");
    userModel.find.mockReturnValueOnce({
      sort: jest.fn().mockRejectedValueOnce(error),
    });
    const consoleSpy = jest.spyOn(console, 'log');
    consoleSpy.mockImplementationOnce(() => {});

    // Act
    await getAllUsersController(req, res);

    // Assert
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.send).toHaveBeenCalledWith({
      success: false,
      message: "Error While Fetching All Users",
      error
    });
    expect(consoleSpy).toHaveBeenCalledWith(error);
  });
});