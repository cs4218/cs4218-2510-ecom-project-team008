import "./orderModel";
import mongoose from "mongoose";
import OrderModel from "./orderModel";
import {expect} from "@playwright/test";

describe('Order Model', () => {
  const mockPayment = {
    errors: {},
    params: {},
    message: "Mock Message",
    success: false,
  };

  const productId1 = new mongoose.Types.ObjectId();
  const productId2 = new mongoose.Types.ObjectId();
  const productId3 = new mongoose.Types.ObjectId();
  const productId4 = new mongoose.Types.ObjectId();

  const invalidPayments = [
    null,
    {},
    {errors: {}},
    {params: {}},
    {errors: {}, params: {}},
    {errors: {}, params: {}, success: false},
    {errors: {}, params: {}, message: "Mock Message"},
    {errors: {}, params: {}, message: "Mock Message", success: "Mock Success"},
  ];
  test.each(invalidPayments)(
    'should fail validation for payment of incorrect shape', async (invalidPayment) => {
      // Arrange
      const buyerId = new mongoose.Types.ObjectId();
      const productId = new mongoose.Types.ObjectId();
      const mockOrder = {
        products: [productId],
        payment: invalidPayment,
        buyer: buyerId
      };

      // Act
      const orderData = new OrderModel(mockOrder);

      // Assert
      await expect(orderData.validate()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('should resolve correctly with valid payment structure', async () => {
    // Arrange
    const buyerId = new mongoose.Types.ObjectId();
    const productId = new mongoose.Types.ObjectId();
    const mockOrder = {
      products: [productId],
      payment: mockPayment,
      buyer: buyerId
    };

    // Act
    const orderData = new OrderModel(mockOrder);

    // Assert
    await expect(orderData.validate).rejects.not.toThrow(mongoose.Error.ValidationError);
  });

  it('should have default status as not process', async () => {
    // Arrange
    const buyerId = new mongoose.Types.ObjectId();
    const productId = new mongoose.Types.ObjectId();
    const mockOrder = {
      products: [productId],
      payment: mockPayment,
      buyer: buyerId
    };

    // Act
    const orderData = new OrderModel(mockOrder);

    // Assert
    expect(orderData.status).toEqual("Not Process");
  });

  const statuses = ["Not Process", "Processing", "Shipped", "delivered", "cancel"];
  test.each(statuses)(
    'should be able to create order of each valid status', (status) => {
      // Arrange
      const buyerId = new mongoose.Types.ObjectId();
      const productId = new mongoose.Types.ObjectId();
      const mockOrder = {
        products: [productId],
        payment: mockPayment,
        buyer: buyerId,
        status
      };

      // Act
      const orderData = new OrderModel(mockOrder);

      // Assert
      expect(orderData.status).toEqual(status);
    }
  );

  const invalidStatuses = [
    null,
    "",
    "    ",
    "InvalidStatus",
    "Invalid Status",
    "123",
    "!@#"
  ];
  test.each(invalidStatuses)(
    'should fail validation for invalid status', async (invalidStatus) => {
    // Arrange
    const buyerId = new mongoose.Types.ObjectId();
    const productId = new mongoose.Types.ObjectId();
    const mockOrder = {
      products: [productId],
      payment: mockPayment,
      buyer: buyerId,
      status: invalidStatus
    };

    // Act
    const orderData = new OrderModel(mockOrder);

    // Assert
    await expect(orderData.validate()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('should be able to accept multiple product ids', () => {
    // Arrange
    const buyerId = new mongoose.Types.ObjectId();
    const mockProducts = [productId1, productId2, productId3, productId4];
    const mockOrder = {
      products: mockProducts,
      payment: mockPayment,
      buyer: buyerId
    };

    // Act
    const orderData = new OrderModel(mockOrder);

    // Assert
    expect(orderData.status).toEqual("Not Process");
    expect(orderData.products).toEqual(mockProducts);
  });

  it('should fail validation if product array is empty', async () => {
    // Arrange
    const buyerId = new mongoose.Types.ObjectId();
    const mockOrder = {
      products: [],
      payment: mockPayment,
      buyer: buyerId
    };

    // Act
    const orderData = new OrderModel(mockOrder);

    // Assert
    await expect(orderData.validate()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  const fields = ["products", "payment", "buyer", "status"];
  test.each(fields)(
    'should fail validation if any required field is missing', async(field) => {
      // Arrange
      const buyerId = new mongoose.Types.ObjectId();
      const mockProducts = [productId1, productId2, productId3, productId4];
      const mockOrder = {
        products: mockProducts,
        payment: mockPayment,
        buyer: buyerId,
        [field]: null
      };

      // Act
      const orderData = new OrderModel(mockOrder);

      // Assert
      await expect(orderData.validate()).rejects.toThrow(mongoose.Error.ValidationError);
  });
});