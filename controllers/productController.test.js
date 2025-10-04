import {
  createProductController,
  getProductController,
  getSingleProductController,
  productPhotoController,
  deleteProductController,
  updateProductController,
  productFiltersController,
  productCountController,
  productListController,
  searchProductController,
  realtedProductController,
  productCategoryController,
} from '../controllers/productController.js';

import productModel from '../models/productModel.js';
import categoryModel from '../models/categoryModel.js';
import orderModel from '../models/orderModel.js';
import fs from 'fs';
import braintree from 'braintree';

// Mock all external dependencies
jest.mock('../models/productModel.js');
jest.mock('../models/categoryModel.js');
jest.mock('../models/orderModel.js');
jest.mock('fs');
jest.mock('slugify', () => jest.fn((str) => str.replace(/\s+/g, '-')));

// Mock braintree with self-contained mocks
jest.mock('braintree', () => ({
  BraintreeGateway: jest.fn().mockImplementation(() => ({
    clientToken: {
      generate: jest.fn()
    },
    transaction: {
      sale: jest.fn()
    }
  })),
  Environment: {
    Sandbox: 'sandbox'
  }
}));

describe('Product Controller Tests', () => {
  let mockReq, mockRes;

  beforeEach(() => {
    // Arrange - Reset mocks and setup common test data
    jest.clearAllMocks();
    
    mockReq = {
      fields: {},
      files: {},
      params: {},
      body: {},
      user: { _id: 'user123' }
    };

    mockRes = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis()
    };
  });

  describe('getProductController', () => {
    it('should get all products successfully', async () => {
      // Arrange
      const mockProducts = [
        { _id: '1', name: 'Product 1', category: 'cat1' },
        { _id: '2', name: 'Product 2', category: 'cat2' }
      ];

      const mockQuery = {
        populate: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        sort: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await getProductController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({});
      expect(mockQuery.populate).toHaveBeenCalledWith('category');
      expect(mockQuery.select).toHaveBeenCalledWith('-photo');
      expect(mockQuery.limit).toHaveBeenCalledWith(12);
      expect(mockQuery.sort).toHaveBeenCalledWith({ createdAt: -1 });
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        counTotal: 2,
        message: 'ALlProducts ',
        products: mockProducts
      });
    });

    it('should handle database errors when getting products', async () => {
      // Arrange
      const error = new Error('Database connection failed');
      productModel.find.mockImplementation(() => {
        throw error;
      });

      // Act
      await getProductController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'Erorr in getting products',
        error: error.message
      });
    });
  });

  describe('getSingleProductController', () => {
    it('should get single product by slug successfully', async () => {
      // Arrange
      mockReq.params.slug = 'test-product';
      const mockProduct = {
        _id: 'product123',
        name: 'Test Product',
        slug: 'test-product'
      };

      const mockQuery = {
        select: jest.fn().mockReturnThis(),
        populate: jest.fn().mockResolvedValue(mockProduct)
      };

      productModel.findOne.mockReturnValue(mockQuery);

      // Act
      await getSingleProductController(mockReq, mockRes);

      // Assert
      expect(productModel.findOne).toHaveBeenCalledWith({ slug: 'test-product' });
      expect(mockQuery.select).toHaveBeenCalledWith('-photo');
      expect(mockQuery.populate).toHaveBeenCalledWith('category');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        message: 'Single Product Fetched',
        product: mockProduct
      });
    });

    it('should handle errors when getting single product', async () => {
      // Arrange
      mockReq.params.slug = 'test-product';
      const error = new Error('Product not found');
      productModel.findOne.mockImplementation(() => {
        throw error;
      });

      // Act
      await getSingleProductController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'Eror while getitng single product',
        error
      });
    });
  });

  describe('productPhotoController', () => {
    it('should return product photo successfully', async () => {
      // Arrange
      mockReq.params.pid = 'product123';
      const mockProduct = {
        photo: {
          data: Buffer.from('image data'),
          contentType: 'image/jpeg'
        }
      };

      const mockQuery = {
        select: jest.fn().mockResolvedValue(mockProduct)
      };

      productModel.findById.mockReturnValue(mockQuery);

      // Act
      await productPhotoController(mockReq, mockRes);

      // Assert
      expect(productModel.findById).toHaveBeenCalledWith('product123');
      expect(mockQuery.select).toHaveBeenCalledWith('photo');
      expect(mockRes.set).toHaveBeenCalledWith('Content-type', 'image/jpeg');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith(mockProduct.photo.data);
    });

    it('should handle errors when getting photo', async () => {
      // Arrange
      mockReq.params.pid = 'product123';
      const error = new Error('Photo not found');
      productModel.findById.mockImplementation(() => {
        throw error;
      });

      // Act
      await productPhotoController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'Erorr while getting photo',
        error
      });
    });
  });

  describe('productFiltersController', () => {
    it('should filter products by category and price', async () => {
      // Arrange
      mockReq.body = {
        checked: ['category1', 'category2'],
        radio: [50, 200]
      };

      const mockProducts = [
        { _id: '1', name: 'Product 1', price: 100 },
        { _id: '2', name: 'Product 2', price: 150 }
      ];

      productModel.find.mockResolvedValue(mockProducts);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        category: ['category1', 'category2'],
        price: { $gte: 50, $lte: 200 }
      });
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        products: mockProducts
      });
    });

    it('should handle empty filters', async () => {
      // Arrange
      mockReq.body = {
        checked: [],
        radio: []
      };

      const mockProducts = [];
      productModel.find.mockResolvedValue(mockProducts);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({});
      expect(mockRes.status).toHaveBeenCalledWith(200);
    });

    it('should handle filter errors', async () => {
      // Arrange
      mockReq.body = {
        checked: ['category1'],
        radio: [50, 200]
      };

      const error = new Error('Filter error');
      productModel.find.mockRejectedValue(error);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'Error WHile Filtering Products',
        error
      });
    });
  });

  describe('productCountController', () => {
    it('should return product count successfully', async () => {
      // Arrange
      const mockQuery = {
        estimatedDocumentCount: jest.fn().mockResolvedValue(50)
      };
      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productCountController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({});
      expect(mockQuery.estimatedDocumentCount).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        total: 50
      });
    });

    it('should handle count errors', async () => {
      // Arrange
      const error = new Error('Count error');
      const mockQuery = {
        estimatedDocumentCount: jest.fn().mockRejectedValue(error)
      };
      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productCountController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        message: 'Error in product count',
        error,
        success: false
      });
    });
  });

  describe('productListController', () => {
    it('should return paginated products', async () => {
      // Arrange
      mockReq.params.page = '2';
      const mockProducts = [
        { _id: '1', name: 'Product 1' },
        { _id: '2', name: 'Product 2' }
      ];

      const mockQuery = {
        select: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        sort: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productListController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({});
      expect(mockQuery.select).toHaveBeenCalledWith('-photo');
      expect(mockQuery.skip).toHaveBeenCalledWith(6); // (2-1) * 6
      expect(mockQuery.limit).toHaveBeenCalledWith(6);
      expect(mockQuery.sort).toHaveBeenCalledWith({ createdAt: -1 });
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        products: mockProducts
      });
    });

    it('should default to page 1 when no page specified', async () => {
      // Arrange
      const mockProducts = [];
      const mockQuery = {
        select: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        sort: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productListController(mockReq, mockRes);

      // Assert
      expect(mockQuery.skip).toHaveBeenCalledWith(0); // (1-1) * 6
    });
  });

  describe('productFiltersController - query construction validation', () => {
    it('should build query with only category filter when price is empty', async () => {
      // Arrange
      mockReq.body = {
        checked: ['cat1', 'cat2'],
        radio: []
      };
      productModel.find.mockResolvedValue([]);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert - Verify EXACT query structure
      expect(productModel.find).toHaveBeenCalledWith({
        category: ['cat1', 'cat2']
        // Should NOT have price field
      });
      
      const callArgs = productModel.find.mock.calls[0][0];
      expect(callArgs).not.toHaveProperty('price');
    });

    it('should build query with only price filter when category is empty', async () => {
      // Arrange
      mockReq.body = {
        checked: [],
        radio: [100, 500]
      };
      productModel.find.mockResolvedValue([]);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        price: { $gte: 100, $lte: 500 }
      });
      
      const callArgs = productModel.find.mock.calls[0][0];
      expect(callArgs).not.toHaveProperty('category');
    });

    it('should handle single category in checked array', async () => {
      // Arrange
      mockReq.body = {
        checked: ['electronics'],
        radio: []
      };
      productModel.find.mockResolvedValue([]);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        category: ['electronics']
      });
    });

    it('should handle price range with same min and max value', async () => {
      // Arrange
      mockReq.body = {
        checked: [],
        radio: [100, 100]
      };
      productModel.find.mockResolvedValue([]);

      // Act
      await productFiltersController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        price: { $gte: 100, $lte: 100 }
      });
    });
  });

  describe('searchProductController', () => {
    it('should search products by keyword', async () => {
      // Arrange
      mockReq.params.keyword = 'laptop';
      const mockProducts = [
        { _id: '1', name: 'Gaming Laptop', description: 'High performance laptop' }
      ];

      const mockQuery = {
        select: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await searchProductController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        $or: [
          { name: { $regex: 'laptop', $options: 'i' } },
          { description: { $regex: 'laptop', $options: 'i' } }
        ]
      });
      expect(mockQuery.select).toHaveBeenCalledWith('-photo');
      expect(mockRes.json).toHaveBeenCalledWith(mockProducts);
    });

    it('should handle search errors', async () => {
      // Arrange
      mockReq.params.keyword = 'laptop';
      const error = new Error('Search error');
      productModel.find.mockImplementation(() => {
        throw error;
      });

      // Act
      await searchProductController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'Error In Search Product API',
        error
      });
    });

    it('should perform case-insensitive search', async () => {
      // Arrange
      mockReq.params.keyword = 'LAPTOP';
      const mockQuery = {
        select: jest.fn().mockResolvedValue([])
      };
      productModel.find.mockReturnValue(mockQuery);

      // Act
      await searchProductController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        $or: [
          { name: { $regex: 'LAPTOP', $options: 'i' } },
          { description: { $regex: 'LAPTOP', $options: 'i' } }
        ]
      });
      
      // Verify the 'i' option is present
      const callArgs = productModel.find.mock.calls[0][0];
      expect(callArgs.$or[0].name.$options).toBe('i');
      expect(callArgs.$or[1].description.$options).toBe('i');
    });

    it('should search with special characters in keyword', async () => {
      // Arrange - Test with special regex characters
      mockReq.params.keyword = 'laptop.pro+';
      const mockQuery = {
        select: jest.fn().mockResolvedValue([])
      };
      productModel.find.mockReturnValue(mockQuery);

      // Act
      await searchProductController(mockReq, mockRes);

      // Assert - Should pass the keyword as-is (MongoDB handles escaping)
      expect(productModel.find).toHaveBeenCalledWith({
        $or: [
          { name: { $regex: 'laptop.pro+', $options: 'i' } },
          { description: { $regex: 'laptop.pro+', $options: 'i' } }
        ]
      });
    });
  });

  describe('realtedProductController', () => {
    it('should return related products', async () => {
      // Arrange
      mockReq.params = { pid: 'product123', cid: 'category456' };
      const mockProducts = [
        { _id: '1', name: 'Related Product 1' },
        { _id: '2', name: 'Related Product 2' }
      ];

      const mockQuery = {
        select: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        populate: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await realtedProductController(mockReq, mockRes);

      // Assert
      expect(productModel.find).toHaveBeenCalledWith({
        category: 'category456',
        _id: { $ne: 'product123' }
      });
      expect(mockQuery.select).toHaveBeenCalledWith('-photo');
      expect(mockQuery.limit).toHaveBeenCalledWith(3);
      expect(mockQuery.populate).toHaveBeenCalledWith('category');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        products: mockProducts
      });
    });

    it('should handle errors when fetching related products', async () => {
      // Arrange
      mockReq.params = { pid: 'product123', cid: 'category456' };
      const error = new Error('Database error');
      productModel.find.mockImplementation(() => {
        throw error;
      });

      // Act
      await realtedProductController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'error while geting related product',
        error
      });
    });
  });

  describe('productCategoryController', () => {
    it('should return products by category', async () => {
      // Arrange
      mockReq.params.slug = 'electronics';
      const mockCategory = { _id: 'cat123', name: 'Electronics', slug: 'electronics' };
      const mockProducts = [
        { _id: '1', name: 'Product 1', category: 'cat123' }
      ];

      categoryModel.findOne.mockResolvedValue(mockCategory);
      const mockQuery = {
        populate: jest.fn().mockResolvedValue(mockProducts)
      };
      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productCategoryController(mockReq, mockRes);

      // Assert
      expect(categoryModel.findOne).toHaveBeenCalledWith({ slug: 'electronics' });
      expect(productModel.find).toHaveBeenCalledWith({ category: mockCategory });
      expect(mockQuery.populate).toHaveBeenCalledWith('category');
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        category: mockCategory,
        products: mockProducts
      });
    });

    it('should handle errors when category is not found', async () => {
      // Arrange
      mockReq.params.slug = 'non-existent';
      const error = new Error('Category not found');
      categoryModel.findOne.mockRejectedValue(error);

      // Act
      await productCategoryController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        error,
        message: 'Error While Getting products'
      });
    });

    it('should handle errors when products query fails', async () => {
      // Arrange
      mockReq.params.slug = 'electronics';
      const mockCategory = { _id: 'cat123', name: 'Electronics' };
      const error = new Error('Products query failed');
      
      categoryModel.findOne.mockResolvedValue(mockCategory);
      productModel.find.mockImplementation(() => {
        throw error;
      });

      // Act
      await productCategoryController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        error,
        message: 'Error While Getting products'
      });
    });
  });

  describe('productPhotoController - edge cases', () => {
    it('should handle product with no photo data', async () => {
      // Arrange
      mockReq.params.pid = 'product123';
      const mockProduct = {
        photo: {
          data: null, // No photo data
          contentType: 'image/jpeg'
        }
      };

      const mockQuery = {
        select: jest.fn().mockResolvedValue(mockProduct)
      };

      productModel.findById.mockReturnValue(mockQuery);

      // Act
      await productPhotoController(mockReq, mockRes);

      // Assert
      expect(productModel.findById).toHaveBeenCalledWith('product123');
      expect(mockQuery.select).toHaveBeenCalledWith('photo');
      // Should not set content type or send data when photo.data is null
      expect(mockRes.set).not.toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalledWith(200);
    });
  });

  describe('productListController - pagination edge cases', () => {
    it('should handle pagination with page parameter as string', async () => {
      // Arrange
      mockReq.params.page = '3'; // String page number
      const mockProducts = [
        { _id: '1', name: 'Product 1' }
      ];

      const mockQuery = {
        select: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        sort: jest.fn().mockResolvedValue(mockProducts)
      };

      productModel.find.mockReturnValue(mockQuery);

      // Act
      await productListController(mockReq, mockRes);

      // Assert
      expect(mockQuery.skip).toHaveBeenCalledWith(12); // (3-1) * 6 = 12
      expect(mockQuery.limit).toHaveBeenCalledWith(6);
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: true,
        products: mockProducts
      });
    });

    it('should handle pagination error', async () => {
      // Arrange
      mockReq.params.page = '2';
      const error = new Error('Pagination error');
      
      productModel.find.mockImplementation(() => {
        throw error;
      });

      // Act
      await productListController(mockReq, mockRes);

      // Assert
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith({
        success: false,
        message: 'error in per page ctrl',
        error
      });
    });
  });
});
