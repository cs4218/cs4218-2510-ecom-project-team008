import React from "react";
import { render, screen } from "@testing-library/react";
import AdminDashboard from "./AdminDashboard";
import { useAuth } from "../../context/auth";

jest.mock("../../components/AdminMenu", () => () => <div data-testid="admin-menu">AdminMenu Mock</div>);
jest.mock("../../components/Layout", () => ({ children }) => (
  <div data-testid="layout">{children}</div>
));

jest.mock("../../context/auth", () => ({
  useAuth: jest.fn(),
}));

describe("AdminDashboard Component", () => {
  const mockAuth = {
    user: {
      name: "Admin",
      email: "admin@example.com",
      phone: "abc123",
    },
  };

  beforeEach(() => {
    useAuth.mockReturnValue([mockAuth]);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test("renders admin information correctly", () => {
    // Arrange
    render(<AdminDashboard />);

    // Act
    const name = screen.getByText(/Admin Name/i);
    const email = screen.getByText(/Admin Email/i);
    const phone = screen.getByText(/Admin Contact/i);

    // Assert
    expect(name).toHaveTextContent("Admin Name : Admin");
    expect(email).toHaveTextContent("Admin Email : admin@example.com");
    expect(phone).toHaveTextContent("Admin Contact : abc123");
  });

  test("renders AdminMenu and Layout components", () => {
    // Arrange
    render(<AdminDashboard />);

    // Act
    const layout = screen.getByTestId("layout");
    const adminMenu = screen.getByTestId("admin-menu");

    // Assert
    expect(layout).toBeInTheDocument();
    expect(adminMenu).toBeInTheDocument();
  });

  test("handles missing auth data", () => {
    // Arrange
    useAuth.mockReturnValue([{}]);
    render(<AdminDashboard />);

    // Act
    const texts = screen.getAllByRole("heading", { level: 3 });

    // Assert — all should render with empty placeholders
    expect(texts[0]).toHaveTextContent("Admin Name :");
    expect(texts[1]).toHaveTextContent("Admin Email :");
    expect(texts[2]).toHaveTextContent("Admin Contact :");
  });
});
