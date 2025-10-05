import React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router-dom";
import UpdateProduct from "./UpdateProduct";
import axios from "axios";
import toast from "react-hot-toast";

// mocks
jest.mock("axios");
jest.mock("react-hot-toast");

// router mocks
const mockNavigate = jest.fn();
const mockParams = { slug: "test-product" };

jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useNavigate: () => mockNavigate,
  useParams: () => mockParams,
}));

// component mocks
jest.mock("./../../components/Layout", () => ({ children, title }) => (
  <div data-testid="layout" data-title={title}>
    {children}
  </div>
));

jest.mock("./../../components/AdminMenu", () => () => (
  <nav data-testid="admin-menu" />
));

jest.mock("antd", () => {
  const Option = ({ children, value }) => (
    <option value={value}>{children}</option>
  );

  const MockSelect = ({ children, onChange, value, placeholder }) => (
    <select
      data-testid={
        placeholder?.includes("category")
          ? "category-select"
          : "shipping-select"
      }
      onChange={(e) => onChange?.(e.target.value)}
      value={value || ""}
    >
      {children}
    </select>
  );

  MockSelect.Option = Option;

  return {
    Select: MockSelect,
    Modal: ({ open, children, onOk, onCancel, title }) =>
      open ? (
        <div data-testid="delete-modal" role="dialog">
          <h2>{title}</h2>
          {children}
          <button onClick={onOk}>Delete</button>
          <button onClick={onCancel}>Cancel</button>
        </div>
      ) : null,
  };
});

// URL mocks
beforeAll(() => {
  global.URL.createObjectURL = jest.fn(() => "blob://test");
  global.URL.revokeObjectURL = jest.fn();
});

afterAll(() => {
  delete global.URL.createObjectURL;
  delete global.URL.revokeObjectURL;
});

// test data
const mockProduct = {
  product: {
    _id: "prod123",
    name: "Test Product",
    description: "Test Description",
    price: 100,
    quantity: 10,
    shipping: true,
    category: { _id: "cat1", name: "Electronics" },
  },
};

const mockCategories = {
  success: true,
  category: [
    { _id: "cat1", name: "Electronics" },
    { _id: "cat2", name: "Books" },
  ],
};

describe("UpdateProduct Component", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockNavigate.mockClear();

    // default API responses
    axios.get.mockImplementation((url) => {
      if (url.includes("get-product")) {
        return Promise.resolve({ data: mockProduct });
      }
      if (url.includes("get-category")) {
        return Promise.resolve({ data: mockCategories });
      }
      return Promise.reject(new Error("Unknown endpoint"));
    });

    axios.put.mockResolvedValue({
      data: { success: true, message: "Updated" },
    });

    axios.delete.mockResolvedValue({
      data: { success: true, message: "Deleted" },
    });
  });

  const renderComponent = () => {
    return render(
      <BrowserRouter>
        <UpdateProduct />
      </BrowserRouter>
    );
  };

  const waitForLoad = async () => {
    await waitFor(() => {
      expect(screen.getByDisplayValue("Test Product")).toBeInTheDocument();
    });
  };

  // rendering test cases
  describe("Component Rendering", () => {
    test("renders page title and main elements", async () => {
      renderComponent();
      await waitForLoad();

      expect(
        screen.getByRole("heading", { name: /update product/i })
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /update product/i })
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /delete product/i })
      ).toBeInTheDocument();
    });

    test("displays product form fields", async () => {
      renderComponent();
      await waitForLoad();

      expect(screen.getByPlaceholderText(/write a name/i)).toBeInTheDocument();
      expect(
        screen.getByPlaceholderText(/write a description/i)
      ).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/write a price/i)).toBeInTheDocument();
      expect(
        screen.getByPlaceholderText(/write a quantity/i)
      ).toBeInTheDocument();
    });

    test("loads and displays categories in select", async () => {
      renderComponent();
      await waitForLoad();

      const categorySelect = screen.getByTestId("category-select");
      const options = within(categorySelect).getAllByRole("option");

      expect(options.length).toBeGreaterThanOrEqual(2);
    });
  });

  // data fetching test cases
  describe("Data Fetching", () => {
    test("fetches product data on mount", async () => {
      renderComponent();

      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(
          "/api/v1/product/get-product/test-product"
        );
      });
    });

    test("fetches categories on mount", async () => {
      renderComponent();

      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith("/api/v1/category/get-category");
      });
    });

    test("handles product fetch error", async () => {
      axios.get.mockImplementation((url) => {
        if (url.includes("get-product")) {
          return Promise.reject(new Error("Network error"));
        }
        return Promise.resolve({ data: mockCategories });
      });

      renderComponent();

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(
          "Something went wrong in getting product"
        );
      });
    });

    test("handles category fetch error", async () => {
      axios.get.mockImplementation((url) => {
        if (url.includes("get-product")) {
          return Promise.resolve({ data: mockProduct });
        }
        return Promise.reject(new Error("Network error"));
      });

      renderComponent();

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(
          "Something went wrong in getting category"
        );
      });
    });

    test("does not populate categories when API returns unsuccessful response", async () => {
      axios.get.mockImplementation((url) => {
        if (url.includes("get-product")) {
          return Promise.resolve({ data: mockProduct });
        }
        return Promise.resolve({ data: { success: false } });
      });

      renderComponent();
      await waitForLoad();

      const categorySelect = screen.getByTestId("category-select");
      const options = within(categorySelect).queryAllByRole("option");

      expect(options.length).toBe(0); // No categories loaded
    });
  });

  // input validation tests (EP/BVA)
  describe("Input Validation", () => {
    test("validates empty product name", async () => {
      renderComponent();
      await waitForLoad();

      const nameInput = screen.getByPlaceholderText(/write a name/i);
      await userEvent.clear(nameInput);

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Product name is required");
      expect(axios.put).not.toHaveBeenCalled();
    });

    test("validates whitespace-only product name", async () => {
      renderComponent();
      await waitForLoad();

      const nameInput = screen.getByPlaceholderText(/write a name/i);
      await userEvent.clear(nameInput);
      await userEvent.type(nameInput, "   ");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Product name is required");
    });

    test("validates empty description", async () => {
      renderComponent();
      await waitForLoad();

      const descInput = screen.getByPlaceholderText(/write a description/i);
      await userEvent.clear(descInput);

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith(
        "Product description is required"
      );
    });

    test("validates zero price", async () => {
      renderComponent();
      await waitForLoad();

      const priceInput = screen.getByPlaceholderText(/write a price/i);
      await userEvent.clear(priceInput);
      await userEvent.type(priceInput, "0");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Price must be greater than 0");
    });

    test("validates negative price", async () => {
      renderComponent();
      await waitForLoad();

      const priceInput = screen.getByPlaceholderText(/write a price/i);
      await userEvent.clear(priceInput);
      await userEvent.type(priceInput, "-5");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Price must be greater than 0");
    });

    test("validates negative quantity", async () => {
      renderComponent();
      await waitForLoad();

      const qtyInput = screen.getByPlaceholderText(/write a quantity/i);
      await userEvent.clear(qtyInput);
      await userEvent.type(qtyInput, "-1");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Quantity cannot be negative");
    });

    test("accepts zero quantity", async () => {
      renderComponent();
      await waitForLoad();

      const qtyInput = screen.getByPlaceholderText(/write a quantity/i);
      await userEvent.clear(qtyInput);
      await userEvent.type(qtyInput, "0");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      // should not throw error
      expect(toast.error).not.toHaveBeenCalledWith(
        "Quantity cannot be negative"
      );
    });

    test("validates missing category", async () => {
      const productNoCategory = {
        product: { ...mockProduct.product, category: { _id: "", name: "" } },
      };

      axios.get.mockImplementation((url) => {
        if (url.includes("get-product")) {
          return Promise.resolve({ data: productNoCategory });
        }
        return Promise.resolve({ data: mockCategories });
      });

      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      expect(toast.error).toHaveBeenCalledWith("Please select a category");
    });
  });

  // user interaction test cases
  describe("User Interactions", () => {
    test("allows editing product name", async () => {
      renderComponent();
      await waitForLoad();

      const nameInput = screen.getByPlaceholderText(/write a name/i);
      await userEvent.clear(nameInput);
      await userEvent.type(nameInput, "Updated Name");

      expect(nameInput).toHaveValue("Updated Name");
    });

    test("allows editing description", async () => {
      renderComponent();
      await waitForLoad();

      const descInput = screen.getByPlaceholderText(/write a description/i);
      await userEvent.clear(descInput);
      await userEvent.type(descInput, "New description");

      expect(descInput).toHaveValue("New description");
    });

    test("allows photo upload", async () => {
      renderComponent();
      await waitForLoad();

      const file = new File(["content"], "test.png", { type: "image/png" });
      const fileInput = screen.getByLabelText(/upload photo/i);

      await userEvent.upload(fileInput, file);

      expect(fileInput.files[0]).toBe(file);
      expect(fileInput.files).toHaveLength(1);
    });

    test("shows photo preview after upload", async () => {
      renderComponent();
      await waitForLoad();

      const file = new File(["content"], "test.png", { type: "image/png" });
      const fileInput = screen.getByLabelText(/upload photo/i);

      await userEvent.upload(fileInput, file);

      await waitFor(() => {
        expect(URL.createObjectURL).toHaveBeenCalledWith(file);
      });
    });

    test("allows selecting category", async () => {
      renderComponent();
      await waitForLoad();

      const categorySelect = screen.getByTestId("category-select");
      await userEvent.selectOptions(categorySelect, "cat2");

      expect(categorySelect).toHaveValue("cat2");
    });

    test("allows selecting shipping option", async () => {
      renderComponent();
      await waitForLoad();

      const shippingSelect = screen.getByTestId("shipping-select");
      await userEvent.selectOptions(shippingSelect, "false");

      expect(shippingSelect).toHaveValue("false");
    });
  });

  // update product test cases
  describe("Update Product", () => {
    test("successfully updates product with valid data", async () => {
      renderComponent();
      await waitForLoad();

      const nameInput = screen.getByPlaceholderText(/write a name/i);
      await userEvent.clear(nameInput);
      await userEvent.type(nameInput, "New Product");

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      await waitFor(() => {
        expect(axios.put).toHaveBeenCalledWith(
          "/api/v1/product/update-product/prod123",
          expect.any(FormData)
        );
      });

      expect(toast.success).toHaveBeenCalledWith(
        "Product Updated Successfully"
      );
      expect(mockNavigate).toHaveBeenCalledWith("/dashboard/admin/products");
    });

    test("includes photo in update when uploaded", async () => {
      renderComponent();
      await waitForLoad();

      const file = new File(["content"], "test.png", { type: "image/png" });
      const fileInput = screen.getByLabelText(/upload photo/i);
      await userEvent.upload(fileInput, file);

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      await waitFor(() => {
        expect(axios.put).toHaveBeenCalled();
      });
    });

    test("handles server error response", async () => {
      axios.put.mockResolvedValueOnce({
        data: { success: false, message: "Update failed" },
      });

      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith("Update failed");
      });

      expect(mockNavigate).not.toHaveBeenCalled();
    });

    test("handles network error", async () => {
      axios.put.mockRejectedValueOnce(new Error("Network error"));

      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /update product/i })
      );

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith("something went wrong");
      });
    });
  });

  // delete product test cases
  describe("Delete Product", () => {
    test("shows delete confirmation modal", async () => {
      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /delete product/i })
      );

      expect(screen.getByTestId("delete-modal")).toBeInTheDocument();
      expect(screen.getByText(/are you sure/i)).toBeInTheDocument();
    });

    test("deletes product when confirmed", async () => {
      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /delete product/i })
      );

      const confirmButton = within(
        screen.getByTestId("delete-modal")
      ).getByText("Delete");
      await userEvent.click(confirmButton);

      await waitFor(() => {
        expect(axios.delete).toHaveBeenCalledWith(
          "/api/v1/product/delete-product/prod123"
        );
      });

      expect(toast.success).toHaveBeenCalledWith(
        "Product Deleted Successfully"
      );
      expect(mockNavigate).toHaveBeenCalledWith("/dashboard/admin/products");
    });

    test("closes modal when cancelled", async () => {
      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /delete product/i })
      );

      const cancelButton = within(screen.getByTestId("delete-modal")).getByText(
        "Cancel"
      );
      await userEvent.click(cancelButton);

      await waitFor(() => {
        expect(screen.queryByTestId("delete-modal")).not.toBeInTheDocument();
      });

      expect(axios.delete).not.toHaveBeenCalled();
    });

    test("handles delete error", async () => {
      axios.delete.mockRejectedValueOnce(new Error("Delete failed"));

      renderComponent();
      await waitForLoad();

      await userEvent.click(
        screen.getByRole("button", { name: /delete product/i })
      );

      const confirmButton = within(
        screen.getByTestId("delete-modal")
      ).getByText("Delete");
      await userEvent.click(confirmButton);

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith("Something went wrong");
      });

      expect(mockNavigate).not.toHaveBeenCalled();
    });
  });

  // memory management test cases
  describe("Memory Management", () => {
    test("cleans up photo URL on unmount", async () => {
      const { unmount } = renderComponent();
      await waitForLoad();

      const file = new File(["content"], "test.png", { type: "image/png" });
      const fileInput = screen.getByLabelText(/upload photo/i);
      await userEvent.upload(fileInput, file);

      await waitFor(() => {
        expect(URL.createObjectURL).toHaveBeenCalled();
      });

      unmount();

      expect(URL.revokeObjectURL).toHaveBeenCalled();
    });

    test("cleans up previous photo URL when new photo uploaded", async () => {
      renderComponent();
      await waitForLoad();

      const file1 = new File(["content1"], "test1.png", { type: "image/png" });
      const file2 = new File(["content2"], "test2.png", { type: "image/png" });
      const fileInput = screen.getByLabelText(/upload photo/i);

      await userEvent.upload(fileInput, file1);
      await waitFor(() =>
        expect(URL.createObjectURL).toHaveBeenCalledWith(file1)
      );

      jest.clearAllMocks();

      await userEvent.upload(fileInput, file2);
      await waitFor(() => {
        expect(URL.createObjectURL).toHaveBeenCalledWith(file2);
        expect(URL.revokeObjectURL).toHaveBeenCalled();
      });
    });
  });

  // edge cases
  describe("Edge Cases", () => {
    test("handles product with null category", async () => {
      const productNullCategory = {
        product: { ...mockProduct.product, category: null },
      };

      axios.get.mockImplementation((url) => {
        if (url.includes("get-product")) {
          return Promise.resolve({ data: productNullCategory });
        }
        return Promise.resolve({ data: mockCategories });
      });

      expect(() => renderComponent()).not.toThrow();
    });

    test("handles very long input values", async () => {
      renderComponent();
      await waitForLoad();

      const longText = "A".repeat(1000);
      const nameInput = screen.getByPlaceholderText(/write a name/i);

      await userEvent.clear(nameInput);
      await userEvent.type(nameInput, longText);

      expect(nameInput).toHaveValue(longText);
    });
  });
});
