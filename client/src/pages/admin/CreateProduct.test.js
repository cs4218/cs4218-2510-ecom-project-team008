import React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router-dom";
import toast from "react-hot-toast";
import axios from "axios";
import CreateProduct from "./CreateProduct";

// mocks
jest.mock("axios", () => ({
  get: jest.fn(),
  post: jest.fn(),
}));

jest.mock("react-hot-toast", () => ({
  success: jest.fn(),
  error: jest.fn(),
}));

// mock useNavigate and keep BrowserRouter real
const mockNavigate = jest.fn();
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useNavigate: () => mockNavigate,
}));

// layout mock to expose title prop
jest.mock("./../../components/Layout", () => (props) => (
  <div data-testid="layout" data-title={props.title}>
    {props.children}
  </div>
));
jest.mock("./../../components/AdminMenu", () => () => (
  <nav data-testid="admin-menu" />
));

// antd mock
jest.mock("antd", () => {
  const MockSelect = ({ children, onChange, placeholder }) => (
    <select
      data-testid={
        placeholder === "Select a category"
          ? "category-select"
          : "shipping-select"
      }
      onChange={(e) => onChange && onChange(e.target.value)}
    >
      <option value="">{`-- ${placeholder} --`}</option>
      {children}
    </select>
  );
  const MockOption = ({ children, value }) => (
    <option value={value}>{children}</option>
  );
  // matches: const { Option } = Select;
  return { Select: Object.assign(MockSelect, { Option: MockOption }) };
});

// helpers
const renderWithRouter = (ui) => render(<BrowserRouter>{ui}</BrowserRouter>);
const fdToObject = (fd) => {
  const o = {};
  fd.forEach((v, k) => (o[k] = v));
  return o;
};
const mockCategories = [
  { _id: "cat1", name: "Electronics" },
  { _id: "cat2", name: "Books" },
];

// Helper to wait for categories to load
const waitForCategoriesToLoad = async () => {
  await waitFor(() => {
    const options = within(screen.getByTestId("category-select")).getAllByRole(
      "option"
    );
    expect(options.length).toBeGreaterThan(1);
  });
};

beforeAll(() => {
  // image preview
  global.URL.createObjectURL = jest.fn(() => "blob://preview");
  global.URL.revokeObjectURL = jest.fn();
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe("CreateProduct – mount & categories", () => {
  test("Fetches and displays categories on mount (success path)", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    expect(
      await screen.findByRole("heading", { name: /create product/i })
    ).toBeInTheDocument();

    // Wait for categories to load
    await waitForCategoriesToLoad();

    const catSelect = screen.getByTestId("category-select");
    const options = within(catSelect).getAllByRole("option");
    // includes placeholder + categories
    expect(options.map((o) => o.textContent)).toEqual([
      "-- Select a category --",
      "Electronics",
      "Books",
    ]);
    expect(axios.get).toHaveBeenCalledWith("/api/v1/category/get-category");
  });

  test("GET resolves with success=false -> categories not set & no toast", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: {
        success: false,
        category: [{ _id: "x", name: "ShouldNotAppear" }],
      },
    });

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    await screen.findByRole("heading", { name: /create product/i });
    const catSelect = screen.getByTestId("category-select");
    expect(
      within(catSelect).queryByText("ShouldNotAppear")
    ).not.toBeInTheDocument();
    expect(toast.error).not.toHaveBeenCalled();
  });

  test("GET throws -> shows listing toast error", async () => {
    // Arrange
    axios.get.mockRejectedValueOnce(new Error("Network error"));

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Something went wrong in getting category"
      )
    );
  });
});

describe("CreateProduct – form inputs", () => {
  test("Updates name input", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const nameInput = await screen.findByPlaceholderText(/write a name/i);

    // Act
    await userEvent.type(nameInput, "iPhone 15");

    // Assert
    expect(nameInput).toHaveValue("iPhone 15");
  });

  test("Updates description textarea", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const desc = await screen.findByPlaceholderText(/write a description/i);

    // Act
    await userEvent.type(desc, "Latest iPhone model");

    // Assert
    expect(desc).toHaveValue("Latest iPhone model");
  });

  test("Updates price (number)", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const price = await screen.findByPlaceholderText(/write a price/i);

    // Act
    await userEvent.type(price, "999");

    // Assert
    expect(price).toHaveValue(999);
  });

  test("Updates quantity (number)", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const qty = await screen.findByPlaceholderText(/write a quantity/i);

    // Act
    await userEvent.type(qty, "50");

    // Assert
    expect(qty).toHaveValue(50);
  });

  test("Selects category from dropdown", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    renderWithRouter(<CreateProduct />);
    await screen.findByRole("heading", { name: /create product/i });

    // Wait for categories to load
    await waitForCategoriesToLoad();

    // Act
    const select = screen.getByTestId("category-select");
    await userEvent.selectOptions(select, "cat1");

    // Assert
    expect(select).toHaveValue("cat1");
  });

  test("Selects shipping option", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const shipping = await screen.findByTestId("shipping-select");

    // Act
    await userEvent.selectOptions(shipping, "1");

    // Assert
    expect(shipping).toHaveValue("1");
  });

  test("Uploads photo and shows preview image & filename", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const file = new File(["photo"], "product.png", { type: "image/png" });
    const input = screen.getByLabelText(/upload photo/i);

    // Act
    await userEvent.upload(input, file);

    // Assert
    expect(input.files[0]).toBe(file);
    expect(input.files).toHaveLength(1);
    await waitFor(() => {
      expect(screen.getByText("product.png")).toBeInTheDocument();
      expect(screen.getByAltText("product_photo")).toBeInTheDocument();
    });
  });

  test("No photo uploaded -> preview not rendered", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    await screen.findByRole("heading", { name: /create product/i });
    expect(screen.queryByAltText("product_photo")).not.toBeInTheDocument();
  });
});

describe("CreateProduct – create (API interactions)", () => {
  test("Success -> toast.success and navigate; FormData contains fields including shipping", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    axios.post.mockResolvedValueOnce({
      data: { success: true, message: "Created" },
    });
    renderWithRouter(<CreateProduct />);

    const file = new File(["img"], "p.png", { type: "image/png" });
    await userEvent.upload(screen.getByLabelText(/upload photo/i), file);
    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "999");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "10"
    );

    // Wait for categories to load
    await waitForCategoriesToLoad();

    // category can be any value; we simulate a value
    await userEvent.selectOptions(
      screen.getByTestId("category-select"),
      "cat1"
    );
    await userEvent.selectOptions(screen.getByTestId("shipping-select"), "1");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledTimes(1);
      const [url, fd] = axios.post.mock.calls[0];
      expect(url).toBe("/api/v1/product/create-product");
      const obj = fdToObject(fd);
      expect(obj.name).toBe("Phone");
      expect(obj.description).toBe("Nice phone");
      expect(obj.price).toBe("999");
      expect(obj.quantity).toBe("10");
      expect(obj.category).toBe("cat1");
      expect(obj.shipping).toBe("1");
      expect(obj.photo).toBeInstanceOf(File);
      expect(obj.photo.name).toBe("p.png");
    });

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Product Created Successfully")
    );
    expect(mockNavigate).toHaveBeenCalledWith("/dashboard/admin/products");
  });

  test("API returns success=false -> toast.error (message) and no navigate", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    axios.post.mockResolvedValueOnce({
      data: { success: false, message: "Duplicate" },
    });
    renderWithRouter(<CreateProduct />);

    // Fill all required fields
    const file = new File(["img"], "p.png", { type: "image/png" });
    await userEvent.upload(screen.getByLabelText(/upload photo/i), file);
    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Description"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "5"
    );
    await waitForCategoriesToLoad();
    await userEvent.selectOptions(
      screen.getByTestId("category-select"),
      "cat1"
    );
    await userEvent.selectOptions(screen.getByTestId("shipping-select"), "1");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("Duplicate"));
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  test("POST throws -> toast.error('Something went wrong creating product') and no navigate", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    axios.post.mockRejectedValueOnce(new Error("server 500"));
    renderWithRouter(<CreateProduct />);

    // Fill all required fields
    const file = new File(["img"], "p.png", { type: "image/png" });
    await userEvent.upload(screen.getByLabelText(/upload photo/i), file);
    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Description"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "5"
    );
    await waitForCategoriesToLoad();
    await userEvent.selectOptions(
      screen.getByTestId("category-select"),
      "cat1"
    );
    await userEvent.selectOptions(screen.getByTestId("shipping-select"), "1");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Something went wrong creating product"
      )
    );
    expect(mockNavigate).not.toHaveBeenCalled();
  });
});

describe("CreateProduct – validation", () => {
  test("Empty name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Product name is required");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Empty description shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith(
      "Product description is required"
    );
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Price <= 0 shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "0");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Price must be greater than 0");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Negative quantity shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "-5"
    );

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Quantity cannot be negative");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Empty quantity shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");

    // Act - don't fill quantity
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Quantity cannot be negative");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Missing category shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "10"
    );

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Please select a category");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Missing photo shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "10"
    );
    await waitForCategoriesToLoad();
    await userEvent.selectOptions(
      screen.getByTestId("category-select"),
      "cat1"
    );

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Please upload a product photo");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Missing shipping shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });
    renderWithRouter(<CreateProduct />);

    const file = new File(["img"], "p.png", { type: "image/png" });
    await userEvent.upload(screen.getByLabelText(/upload photo/i), file);
    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "Nice phone"
    );
    await userEvent.type(screen.getByPlaceholderText(/write a price/i), "100");
    await userEvent.type(
      screen.getByPlaceholderText(/write a quantity/i),
      "10"
    );
    await waitForCategoriesToLoad();
    await userEvent.selectOptions(
      screen.getByTestId("category-select"),
      "cat1"
    );

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Please select shipping option");
    expect(axios.post).not.toHaveBeenCalled();
  });
});

describe("CreateProduct – edge cases", () => {
  test("Very long product name accepted by input", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);
    const name = await screen.findByPlaceholderText(/write a name/i);
    const longName = "A".repeat(500);

    // Act
    await userEvent.type(name, longName);

    // Assert
    expect(name).toHaveValue(longName);
  });

  test("Whitespace-only name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "   ");

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Product name is required");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("Whitespace-only description shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    renderWithRouter(<CreateProduct />);

    await userEvent.type(screen.getByPlaceholderText(/write a name/i), "Phone");
    await userEvent.type(
      screen.getByPlaceholderText(/write a description/i),
      "   "
    );

    // Act
    await userEvent.click(
      screen.getByRole("button", { name: /create product/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith(
      "Product description is required"
    );
    expect(axios.post).not.toHaveBeenCalled();
  });
});

describe("CreateProduct – basic rendering & layout", () => {
  test("Renders key widgets: menus, inputs, selects, button", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: mockCategories },
    });

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    await screen.findByRole("heading", { name: /create product/i });
    expect(screen.getByTestId("admin-menu")).toBeInTheDocument();
    expect(screen.getByTestId("category-select")).toBeInTheDocument();
    expect(screen.getByTestId("shipping-select")).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/write a name/i)).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/write a description/i)
    ).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/write a price/i)).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/write a quantity/i)
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /create product/i })
    ).toBeInTheDocument();
  });

  test("Layout receives correct title prop", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });

    // Act
    renderWithRouter(<CreateProduct />);

    // Assert
    await screen.findByRole("heading", { name: /create product/i });
    const layout = screen.getByTestId("layout");
    expect(layout).toHaveAttribute("data-title", "Dashboard - Create Product");
  });
});
