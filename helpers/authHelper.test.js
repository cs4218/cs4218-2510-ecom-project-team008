import bcrypt from "bcrypt";
import { hashPassword, comparePassword } from "./authHelper";

jest.mock("bcrypt");

describe("authHelper", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('hashPassword', () => {
    test('should hash password using bcrypt with saltRounds = 10', async () => {
      // Arrange
      const passwordInput = 'mockPassword';
      const mockHashedPassword = 'hashedPassword123';
      bcrypt.hash.mockResolvedValue(mockHashedPassword);

      // Act
      const result = await hashPassword(passwordInput);

      // Assert
      expect(bcrypt.hash).toHaveBeenCalledWith(passwordInput, 10);
      expect(result).toBe(mockHashedPassword);
    });

    test("should log error and return undefined if bcrypt.hash throws", async () => {
      // Arrange
      const passwordInput = "mockPassword";
      const error = new Error("Hash failed");
      bcrypt.hash.mockRejectedValue(error);
      const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});

      // Act
      const result = await hashPassword(passwordInput);

      // Assert
      expect(consoleSpy).toHaveBeenCalledWith(error);
      expect(result).toBeUndefined();

      consoleSpy.mockRestore();
    });
  });


  describe("comparePassword", () => {
    test("should return true when passwords match", async () => {
      // Arrange
      const plain = "correctPassword";
      const hashed = "hashedPassword";
      bcrypt.compare.mockResolvedValue(true);

      // Act
      const result = await comparePassword(plain, hashed);

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith(plain, hashed);
      expect(result).toBeTruthy();
    });

    test("should return false when passwords do not match", async () => {
      // Arrange
      const plain = "wrongPassword";
      const hashed = "hashedPassword";
      bcrypt.compare.mockResolvedValue(false);

      // Act
      const result = await comparePassword(plain, hashed);

      // Assert
      expect(bcrypt.compare).toHaveBeenCalledWith(plain, hashed);
      expect(result).toBeFalsy();
    });
  });
})