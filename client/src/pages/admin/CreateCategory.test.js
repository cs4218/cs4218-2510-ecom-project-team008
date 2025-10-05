import React from "react";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import toast from "react-hot-toast";
import axios from "axios";
import CreateCategory from "./CreateCategory.js";

// mock (axios)
jest.mock("axios", () => ({
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
}));

// mock (toast)
jest.mock("react-hot-toast", () => ({
  success: jest.fn(),
  error: jest.fn(),
}));

// renders children when open === true, exposes a close button that triggers onCancel
jest.mock("antd", () => ({
  Modal: ({ open, children, onCancel }) =>
    open ? (
      <div data-testid="modal">
        <button data-testid="modal-close" onClick={onCancel}>
          Close
        </button>
        {children}
      </div>
    ) : null,
}));

// stubs
jest.mock("./../../components/Layout", () => ({ children }) => (
  <div data-testid="layout">{children}</div>
));
jest.mock("./../../components/AdminMenu", () => () => (
  <nav data-testid="admin-menu" />
));

// mock CategoryForm exposing (handleSubmit, value, setValue)
jest.mock("../../components/Form/CategoryForm", () => (props) => {
  const { handleSubmit, value, setValue } = props;
  return (
    <form onSubmit={(e) => handleSubmit(e)}>
      <input
        aria-label="category-input"
        placeholder="Enter new category"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button type="submit">Submit</button>
    </form>
  );
});

const api = {
  list: "/api/v1/category/get-category",
  create: "/api/v1/category/create-category",
  update: (id) => `/api/v1/category/update-category/${id}`,
  del: (id) => `/api/v1/category/delete-category/${id}`,
};

const rows = () => screen.getAllByRole("row");
const findRowByName = (name) =>
  screen.getAllByRole("row").find((r) => within(r).queryByText(name));

describe("CreateCategory", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("mount: fetches and displays categories", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: {
        success: true,
        category: [
          { _id: "1", name: "Books" },
          { _id: "2", name: "Music" },
        ],
      },
    });

    // Act
    render(<CreateCategory />);

    // Assert
    expect(await screen.findByText("Manage Category")).toBeInTheDocument();
    await waitFor(() => expect(rows().length).toBeGreaterThanOrEqual(3));
    expect(findRowByName("Books")).toBeTruthy();
    expect(findRowByName("Music")).toBeTruthy();
  });

  test("create: success path calls POST, refetches and toasts", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    axios.post.mockResolvedValueOnce({ data: { success: true } });
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "9", name: "Gadgets" }] },
    });

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.type(input, "Gadgets");
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith(api.create, { name: "Gadgets" })
    );
    expect(toast.success).toHaveBeenCalledWith("Gadgets is created");
    await waitFor(() => expect(findRowByName("Gadgets")).toBeTruthy());
  });

  test("create: API returns success=false shows toast.error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    axios.post.mockResolvedValueOnce({
      data: { success: false, message: "duplicate" },
    });

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.type(input, "Books");
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("duplicate")
    );
  });

  test("create: POST throws -> shows specific catch toast", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    axios.post.mockRejectedValueOnce(new Error("network down"));

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.type(input, "Any");
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Something went wrong in input form"
      )
    );
  });

  test("create: empty name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.clear(input);
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Category name is required");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("create: whitespace-only name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.type(input, "   ");
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Category name is required");
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("update: clicking Edit opens modal with prefilled name; success path resets & refetches", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "Old" }] },
    });
    axios.put.mockResolvedValueOnce({ data: { success: true } });
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "New" }] },
    });

    render(<CreateCategory />);
    await screen.findByText("Old");

    // Act
    const row = findRowByName("Old");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);

    await userEvent.clear(modalInput);
    await userEvent.type(modalInput, "New");
    await userEvent.click(
      within(modal).getByRole("button", { name: /submit/i })
    );

    // Assert
    await waitFor(() =>
      expect(axios.put).toHaveBeenCalledWith(api.update("1"), { name: "New" })
    );
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("New is updated")
    );
    await waitFor(() =>
      expect(screen.queryByTestId("modal")).not.toBeInTheDocument()
    );
    await waitFor(() => expect(findRowByName("New")).toBeTruthy());
  });

  test("update: API returns success=false shows toast.error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "Alpha" }] },
    });
    axios.put.mockResolvedValueOnce({
      data: { success: false, message: "nope" },
    });

    render(<CreateCategory />);
    await screen.findByText("Alpha");

    // Act
    const row = findRowByName("Alpha");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);
    await userEvent.clear(modalInput);
    await userEvent.type(modalInput, "Beta");
    await userEvent.click(
      within(modal).getByRole("button", { name: /submit/i })
    );

    // Assert
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("nope"));
    expect(screen.getByTestId("modal")).toBeInTheDocument();
  });

  test("update: PUT throws -> shows catch toast", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "7", name: "Gamma" }] },
    });
    axios.put.mockRejectedValueOnce(new Error("server 500"));

    render(<CreateCategory />);
    await screen.findByText("Gamma");

    // Act
    const row = findRowByName("Gamma");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);
    await userEvent.clear(modalInput);
    await userEvent.type(modalInput, "Delta");
    await userEvent.click(
      within(modal).getByRole("button", { name: /submit/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith(
      "An error occurred while updating category"
    );
  });

  test("update: clicking modal close button hides modal", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "5", name: "Test" }] },
    });

    render(<CreateCategory />);
    await screen.findByText("Test");

    // Act
    const row = findRowByName("Test");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    expect(modal).toBeInTheDocument();

    const closeBtn = screen.getByTestId("modal-close");
    await userEvent.click(closeBtn);

    // Assert
    await waitFor(() =>
      expect(screen.queryByTestId("modal")).not.toBeInTheDocument()
    );
  });

  test("update: modal input is prefilled with the selected category name", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "PrefillMe" }] },
    });

    render(<CreateCategory />);
    await screen.findByText("PrefillMe");

    // Act
    const row = findRowByName("PrefillMe");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    // Assert
    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);
    expect(modalInput).toHaveValue("PrefillMe");
  });

  test("update: empty name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "OldName" }] },
    });

    render(<CreateCategory />);
    await screen.findByText("OldName");

    // Act
    const row = findRowByName("OldName");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);
    await userEvent.clear(modalInput);
    await userEvent.click(
      within(modal).getByRole("button", { name: /submit/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Category name is required");
    expect(axios.put).not.toHaveBeenCalled();
  });

  test("update: whitespace-only name shows validation error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "1", name: "OldName" }] },
    });

    render(<CreateCategory />);
    await screen.findByText("OldName");

    // Act
    const row = findRowByName("OldName");
    const editBtn = within(row).getByRole("button", { name: /edit/i });
    await userEvent.click(editBtn);

    const modal = await screen.findByTestId("modal");
    const modalInput =
      within(modal).getByPlaceholderText(/enter new category/i);
    await userEvent.clear(modalInput);
    await userEvent.type(modalInput, "   ");
    await userEvent.click(
      within(modal).getByRole("button", { name: /submit/i })
    );

    // Assert
    expect(toast.error).toHaveBeenCalledWith("Category name is required");
    expect(axios.put).not.toHaveBeenCalled();
  });

  test("delete: success path toasts and refetches", async () => {
    // Arrange
    axios.get
      .mockResolvedValueOnce({
        data: { success: true, category: [{ _id: "3", name: "Zeta" }] },
      })
      .mockResolvedValueOnce({ data: { success: true, category: [] } });
    axios.delete.mockResolvedValueOnce({ data: { success: true } });

    render(<CreateCategory />);
    await screen.findByText("Zeta");

    // Act
    const row = findRowByName("Zeta");
    const delBtn = within(row).getByRole("button", { name: /delete/i });
    await userEvent.click(delBtn);

    // Assert
    expect(axios.delete).toHaveBeenCalledWith(api.del("3"));
    expect(toast.success).toHaveBeenCalledWith("Category is deleted");
    await waitFor(() => expect(findRowByName("Zeta")).toBeFalsy());
  });

  test("delete: API returns success=false shows toast.error", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "10", name: "KeepMe" }] },
    });
    axios.delete.mockResolvedValueOnce({
      data: { success: false, message: "blocked" },
    });

    render(<CreateCategory />);
    await screen.findByText("KeepMe");

    // Act
    const row = findRowByName("KeepMe");
    const delBtn = within(row).getByRole("button", { name: /delete/i });
    await userEvent.click(delBtn);

    // Assert
    expect(toast.error).toHaveBeenCalledWith("blocked");
    expect(findRowByName("KeepMe")).toBeTruthy();
  });

  test("delete: when API returns success=false, it does NOT refetch", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "10", name: "KeepMe" }] },
    });
    axios.delete.mockResolvedValueOnce({
      data: { success: false, message: "blocked" },
    });

    render(<CreateCategory />);
    await screen.findByText("KeepMe");

    // Act
    const row = findRowByName("KeepMe");
    const delBtn = within(row).getByRole("button", { name: /delete/i });
    await userEvent.click(delBtn);

    // Assert
    expect(axios.get).toHaveBeenCalledTimes(1); // only initial fetch
  });

  test("delete: DELETE throws -> shows catch toast", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({
      data: { success: true, category: [{ _id: "77", name: "Won'tDelete" }] },
    });
    axios.delete.mockRejectedValueOnce(new Error("timeout"));

    render(<CreateCategory />);
    await screen.findByText("Won'tDelete");

    // Act
    const row = findRowByName("Won'tDelete");
    const delBtn = within(row).getByRole("button", { name: /delete/i });
    await userEvent.click(delBtn);

    // Assert
    expect(toast.error).toHaveBeenCalledWith(
      "An error occurred while deleting category"
    );
  });

  test("create: when API returns success=false, it does NOT refetch", async () => {
    // Arrange
    axios.get.mockResolvedValueOnce({ data: { success: true, category: [] } });
    axios.post.mockResolvedValueOnce({
      data: { success: false, message: "duplicate" },
    });

    render(<CreateCategory />);
    const input = await screen.findByPlaceholderText(/enter new category/i);

    // Act
    await userEvent.type(input, "Books");
    await userEvent.click(screen.getByRole("button", { name: /submit/i }));

    // Assert
    expect(axios.get).toHaveBeenCalledTimes(1); // only initial fetch
  });

  test("mount: GET throws -> shows error toast for listing", async () => {
    // Arrange
    axios.get.mockRejectedValueOnce(new Error("boom"));

    // Act
    render(<CreateCategory />);

    // Assert
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Something went wrong in getting category"
      )
    );
  });
});

test("mount: GET resolves with success=false -> does not update list", async () => {
  // Arrange
  axios.get.mockResolvedValueOnce({
    data: { success: false, category: [{ _id: "x", name: "ShouldNotAppear" }] },
  });

  // Act
  render(<CreateCategory />);

  // Assert
  expect(await screen.findByText("Manage Category")).toBeInTheDocument();
  // list should not be updated because success=false branch was taken
  expect(screen.queryByText("ShouldNotAppear")).not.toBeInTheDocument();
});
