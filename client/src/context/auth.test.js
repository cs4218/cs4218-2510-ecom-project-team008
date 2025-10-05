import React from "react";
import { render, screen, act, fireEvent } from "@testing-library/react";
import axios from "axios";
import { AuthProvider, useAuth } from "./auth.js";

const mockStorage = {};
beforeAll(() => {
  Storage.prototype.getItem = jest.fn((key) => mockStorage[key] || null);
  Storage.prototype.setItem = jest.fn((key, value) => { mockStorage[key] = value; });
});

const TestComponent = () => { // so that I can test that children components can access the values
  const [auth, setAuth] = useAuth();

  return (
    <div>
      <p data-testid="user">{auth.user ? auth.user.name : "No user"}</p>
      <p data-testid="token">{auth.token || "No token"}</p>
      <button
        data-testid="update-btn"
        onClick={() => setAuth({ user: { name: "updatedName" }, token: "updatedToken" })}
      >
        Update Auth
      </button>
    </div>
  );
};

describe("AuthProvider and useAuth", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    delete axios.defaults.headers.common["Authorization"];
    for (let key in mockStorage) delete mockStorage[key];
  });

  test("should provide default auth values", () => {
    // Act
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    // Assert
    expect(screen.getByTestId("user").textContent).toBe("No user");
    expect(screen.getByTestId("token").textContent).toBe("No token");
  });

  test("should set default axios header based on auth token", () => {
    // Act
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    // Assert
    expect(axios.defaults.headers.common["Authorization"]).toBe("");
  });

  test("should load auth data from localStorage on component mount", async () => {
    // Arrange
    const mockData = {
      user: { name: "existingUser" },
      token: "existingToken",
    };
    mockStorage["auth"] = JSON.stringify(mockData);

    // Act
    await act(async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );
    });

    // Assert
    expect(localStorage.getItem).toHaveBeenCalledWith("auth");
    expect(screen.getByTestId("user").textContent).toBe("existingUser");
    expect(screen.getByTestId("token").textContent).toBe("existingToken");
  });

  test("should update auth state when setAuth is called", async () => {
    // Arrange
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    // Act
    await act(async () => {
      fireEvent.click(screen.getByTestId("update-btn"));
    });

    // Assert
    expect(screen.getByTestId("user").textContent).toBe("updatedName");
    expect(screen.getByTestId("token").textContent).toBe("updatedToken");
    expect(axios.defaults.headers.common["Authorization"]).toBe("updatedToken");
  });

  test("should store default user state values if localStorage auth does not contain object user and token data", async () => {
    // Arrange
    mockStorage["auth"] = "{}";

    // Act
    await act(async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );
    });

    // Assert
    expect(screen.getByTestId("user").textContent).toBe("No user");
    expect(screen.getByTestId("token").textContent).toBe("No token");
  });

  test("should not break if localStorage auth contains invalid jsons string and removes the invalid data", async () => {
    // Arrange
    mockStorage["auth"] = "invalid-json";
    const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    const removeSpy = jest.spyOn(Storage.prototype, "removeItem");
    const parseSpy = jest.spyOn(JSON, "parse").mockImplementation(() => {
      throw new Error("Mocked JSON parse error");
    });

    // Act
    await act(async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );
    });

    // Assert
    expect(consoleSpy).toHaveBeenCalledWith(
      "Failed to parse auth data in local storage",
      expect.any(Error)
    );
    expect(removeSpy).toHaveBeenCalledWith("auth");
    expect(screen.getByTestId("user").textContent).toBe("No user");
    expect(screen.getByTestId("token").textContent).toBe("No token");

    parseSpy.mockRestore();
    consoleSpy.mockRestore();
  });
});
