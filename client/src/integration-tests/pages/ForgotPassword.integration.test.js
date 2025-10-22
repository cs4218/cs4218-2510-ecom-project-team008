import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom/extend-expect";
import axios from "axios";
import toast from "react-hot-toast";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "../../context/auth";
import { CartProvider } from "../../context/cart";
import { SearchProvider } from "../../context/search";
import ForgotPassword from "../../pages/Auth/ForgotPassword";

jest.mock("axios");
jest.mock("react-hot-toast", () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock("../../components/Layout", () => ({
  __esModule: true,
  default: ({ children }) => <div data-testid="mock-layout">{children}</div>,
}));

const Providers = ({ children }) => (
  <AuthProvider>
    <SearchProvider>
      <CartProvider>{children}</CartProvider>
    </SearchProvider>
  </AuthProvider>
);

const Routers = ({ children }) => (
  <MemoryRouter initialEntries={["/forgot-password"]}>
    <Routes>
      <Route path="/forgot-password" element={children} />
      <Route path="/login" element={<div>🔐 Login Page</div>} />
      <Route path="/" element={<div>🏠 Home Page</div>} />
    </Routes>
  </MemoryRouter>
);

describe("Integration between Forgot Password page and frontend dependencies", () => {
  const validInputs = {
    email: "mockuser@email.com",
    password: "newpassword123",
    answer: "mockAnswer",
  };

  const mockUser = {
    name: "Mock User",
    email: "mockuser@email.com",
    phone: "91234567",
    address: "Mock Address",
    role: 0,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
  });

  it("renders forgot password form correctly", async () => {
    render(
      <Providers>
        <Routers>
          <ForgotPassword />
        </Routers>
      </Providers>
    );

    expect(screen.getByText("RESET PASSWORD FORM")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter Your Email")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter Your New Password")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter Your Security Answer")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "RESET PASSWORD" })).toBeInTheDocument();
  });

  it("resets password successfully and redirects to login page", async () => {
    axios.post.mockResolvedValueOnce({
      data: {
        success: true,
        message: "Password reset successful",
        user: mockUser,
        token: "mock-token-123",
      },
    });

    render(
      <Providers>
        <Routers>
          <ForgotPassword />
        </Routers>
      </Providers>
    );

    await userEvent.type(screen.getByPlaceholderText("Enter Your Email"), validInputs.email);
    await userEvent.type(screen.getByPlaceholderText("Enter Your New Password"), validInputs.password);
    await userEvent.type(screen.getByPlaceholderText("Enter Your Security Answer"), validInputs.answer);
    await userEvent.click(screen.getByRole("button", { name: "RESET PASSWORD" }));

    await waitFor(() =>
      expect(axios.post).toHaveBeenCalledWith("/api/v1/auth/forgot-password", {
        email: validInputs.email,
        answer: validInputs.answer,
        newPassword: validInputs.password,
      })
    );

    await waitFor(() => expect(screen.getByText("🔐 Login Page")).toBeInTheDocument());

    const storedAuth = JSON.parse(localStorage.getItem("auth"));
    expect(storedAuth.user.email).toBe(mockUser.email);
    expect(storedAuth.token).toBe("mock-token-123");

    expect(toast.success).toHaveBeenCalledWith("Password reset successful", expect.any(Object));
  });

  it("shows backend error message when reset fails", async () => {
    axios.post.mockResolvedValueOnce({
      data: { success: false, message: "Invalid answer provided" },
    });

    render(
      <Providers>
        <Routers>
          <ForgotPassword />
        </Routers>
      </Providers>
    );

    await userEvent.type(screen.getByPlaceholderText("Enter Your Email"), validInputs.email);
    await userEvent.type(screen.getByPlaceholderText("Enter Your New Password"), validInputs.password);
    await userEvent.type(screen.getByPlaceholderText("Enter Your Security Answer"), validInputs.answer);
    await userEvent.click(screen.getByRole("button", { name: "RESET PASSWORD" }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("Invalid answer provided")
    );
  });

  it("displays generic error message when API call fails", async () => {
    axios.post.mockRejectedValueOnce({
      response: { data: { message: "Server unavailable" } },
    });

    render(
      <Providers>
        <Routers>
          <ForgotPassword />
        </Routers>
      </Providers>
    );

    await userEvent.type(screen.getByPlaceholderText("Enter Your Email"), validInputs.email);
    await userEvent.type(screen.getByPlaceholderText("Enter Your New Password"), validInputs.password);
    await userEvent.type(screen.getByPlaceholderText("Enter Your Security Answer"), validInputs.answer);
    await userEvent.click(screen.getByRole("button", { name: "RESET PASSWORD" }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("Server unavailable")
    );
  });

  it("keeps password field masked while typing", async () => {
    render(
      <Providers>
        <Routers>
          <ForgotPassword />
        </Routers>
      </Providers>
    );

    const passwordInput = screen.getByPlaceholderText("Enter Your New Password");
    expect(passwordInput).toHaveAttribute("type", "password");
  });
});
