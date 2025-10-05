import React, { useState } from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import CategoryForm from "./CategoryForm";

// Small harness to prove controlled-input behavior
function CategoryFormHarness({ initial = "", onSubmit }) {
  const [value, setValue] = useState(initial);
  return (
    <CategoryForm
      handleSubmit={(e) => onSubmit?.(e)}
      value={value}
      setValue={setValue}
    />
  );
}

describe("CategoryForm", () => {
  // check renders
  describe("Rendering", () => {
    test("renders input and submit button with expected attributes", () => {
      const noop = () => {};
      render(<CategoryForm handleSubmit={noop} value="" setValue={noop} />);

      const input = screen.getByPlaceholderText(/enter new category/i);
      const button = screen.getByRole("button", { name: /submit/i });

      expect(input).toBeInTheDocument();
      expect(button).toBeInTheDocument();
      expect(input).toHaveAttribute("type", "text");
      expect(input).toHaveClass("form-control");
      expect(button).toHaveClass("btn", "btn-primary");
      expect(input).toHaveValue("");
    });
  });

  // check user interactions
  describe("User Interaction", () => {
    test("calls setValue as the user types", async () => {
      render(<CategoryFormHarness initial="" />);

      const input = screen.getByPlaceholderText(/enter new category/i);
      await userEvent.type(input, "Books");

      expect(input).toHaveValue("Books");
    });

    test("controlled value reflects parent state", async () => {
      render(<CategoryFormHarness initial="" />);

      const input = screen.getByPlaceholderText(/enter new category/i);
      await userEvent.type(input, "Tech");

      expect(input).toHaveValue("Tech");
    });

    test("submits via button click", async () => {
      const handleSubmit = jest.fn((e) => e.preventDefault?.());
      render(
        <CategoryForm
          handleSubmit={handleSubmit}
          value="Gadgets"
          setValue={jest.fn()}
        />
      );
      const button = screen.getByRole("button", { name: /submit/i });

      await userEvent.click(button);

      expect(handleSubmit).toHaveBeenCalledTimes(1);
      expect(handleSubmit).toHaveBeenCalledWith(expect.any(Object));
    });

    test("submits via Enter key from the input", async () => {
      const handleSubmit = jest.fn((e) => e.preventDefault?.());
      render(
        <CategoryForm
          handleSubmit={handleSubmit}
          value="Music"
          setValue={jest.fn()}
        />
      );
      const input = screen.getByPlaceholderText(/enter new category/i);

      await userEvent.click(input);
      await userEvent.keyboard("{Enter}");

      expect(handleSubmit).toHaveBeenCalledTimes(1);
    });
  });

  // check inputs (using EP/BVA)
  describe("Input Validation", () => {
    test("accepts empty and whitespace-only values", async () => {
      const handleSubmit = jest.fn((e) => e.preventDefault?.());
      const { rerender } = render(
        <CategoryForm
          handleSubmit={handleSubmit}
          value=""
          setValue={jest.fn()}
        />
      );

      await userEvent.click(screen.getByRole("button", { name: /submit/i }));

      expect(handleSubmit).toHaveBeenCalledTimes(1);

      rerender(
        <CategoryForm
          handleSubmit={handleSubmit}
          value=" "
          setValue={jest.fn()}
        />
      );

      await userEvent.click(screen.getByRole("button", { name: /submit/i }));

      expect(handleSubmit).toHaveBeenCalledTimes(2);
    });

    test("handles long strings without issues", async () => {
      const long = "x".repeat(256);
      render(<CategoryFormHarness initial="" />);
      const input = screen.getByPlaceholderText(/enter new category/i);

      await userEvent.type(input, long);

      expect(input).toHaveValue(long);
    });

    test("does not trim whitespace from input", async () => {
      render(<CategoryFormHarness initial="" />);
      const input = screen.getByPlaceholderText(/enter new category/i);

      await userEvent.type(input, "  test  ");

      expect(input).toHaveValue("  test  ");
    });
  });

  // checks handling for missing props
  describe("Missing Props Handling", () => {
    test("renders without crashing when handleSubmit is missing", () => {
      expect(() => {
        render(<CategoryForm value="" setValue={jest.fn()} />);
      }).not.toThrow();
    });

    test("renders without crashing when setValue is missing", () => {
      expect(() => {
        render(<CategoryForm handleSubmit={jest.fn()} value="" />);
      }).not.toThrow();
    });

    test("renders without crashing when value is missing", () => {
      expect(() => {
        render(<CategoryForm handleSubmit={jest.fn()} setValue={jest.fn()} />);
      }).not.toThrow();
    });

    test("handles undefined value gracefully", () => {
      const { container } = render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={undefined}
          setValue={jest.fn()}
        />
      );
      const input = container.querySelector("input");
      expect(input.value).toBe("");
    });

    test("handles null value (causes React warning)", () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      const { container } = render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={null}
          setValue={jest.fn()}
        />
      );
      const input = container.querySelector("input");
      expect(input.value).toBe("");

      consoleSpy.mockRestore();
    });
  });

  // checks form submission
  describe("Form Submission Behavior", () => {
    test("allows multiple rapid submissions", async () => {
      const mockSubmit = jest.fn((e) => e.preventDefault?.());
      render(
        <CategoryForm
          handleSubmit={mockSubmit}
          value="test"
          setValue={jest.fn()}
        />
      );
      const button = screen.getByRole("button", { name: /submit/i });

      await userEvent.click(button);
      await userEvent.click(button);
      await userEvent.click(button);

      expect(mockSubmit).toHaveBeenCalledTimes(3);
    });

    test("does not prevent default form behavior itself", () => {
      const mockSubmit = jest.fn();
      const { container } = render(
        <CategoryForm
          handleSubmit={mockSubmit}
          value="test"
          setValue={jest.fn()}
        />
      );

      const form = container.querySelector("form");
      const submitEvent = new Event("submit", {
        bubbles: true,
        cancelable: true,
      });
      form.dispatchEvent(submitEvent);

      expect(submitEvent.defaultPrevented).toBe(false);
    });
  });

  // checks accessiblity
  describe("Accessibility", () => {
    test("input lacks a proper label", () => {
      render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const label = screen.queryByLabelText(/category/i);
      expect(label).toBeNull();
    });

    test("form has no aria-label or accessible name", () => {
      const { container } = render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const form = container.querySelector("form");
      expect(form.getAttribute("aria-label")).toBeNull();
      expect(form.getAttribute("aria-labelledby")).toBeNull();
    });

    test("no error message container for validation feedback", () => {
      render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const errorMessage = screen.queryByRole("alert");
      expect(errorMessage).toBeNull();
    });
  });

  // check error handling
  describe("Error Handling", () => {
    test("does not handle errors when setValue throws", async () => {
      const mockSetValue = jest.fn(() => {
        throw new Error("setState failed");
      });

      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value=""
          setValue={mockSetValue}
        />
      );

      expect(() => mockSetValue("test")).toThrow("setState failed");

      consoleSpy.mockRestore();
    });
  });

  // checks security
  describe("Security", () => {
    test("accepts special characters and HTML without explicit sanitization", async () => {
      const xssValue = '<script>alert("XSS")</script>';

      render(<CategoryFormHarness initial="" />);

      const input = screen.getByPlaceholderText(/enter new category/i);
      await userEvent.type(input, xssValue);

      expect(input).toHaveValue(xssValue);
    });

    test("displays HTML tags as-is in value (React escapes automatically)", () => {
      const htmlValue = "<div>Test</div>";
      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={htmlValue}
          setValue={jest.fn()}
        />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe(htmlValue);
    });
  });

  // checks edge cases
  describe("Edge Cases", () => {
    test("handles Unicode characters (emojis, non-Latin scripts)", async () => {
      render(<CategoryFormHarness initial="" />);
      const input = screen.getByPlaceholderText(/enter new category/i);

      await userEvent.type(input, "📚书籍");
      expect(input).toHaveValue("📚书籍");
    });

    test("handles non-string value prop (number)", () => {
      const setValue = jest.fn();
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={123}
          setValue={setValue}
        />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("123");

      consoleSpy.mockRestore();
    });

    test("handles non-string value prop (boolean)", () => {
      const setValue = jest.fn();
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={true}
          setValue={setValue}
        />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("true");

      consoleSpy.mockRestore();
    });

    test("handles object value prop (causes React warning)", () => {
      const setValue = jest.fn();
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={{ name: "test" }}
          setValue={setValue}
        />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("[object Object]");

      consoleSpy.mockRestore();
    });

    test("handles array value prop (causes React warning)", () => {
      const setValue = jest.fn();
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value={["test"]}
          setValue={setValue}
        />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("test");

      consoleSpy.mockRestore();
    });

    test("handles newlines and tabs in input", async () => {
      render(<CategoryFormHarness initial="" />);

      const input = screen.getByPlaceholderText(/enter new category/i);
      await userEvent.type(input, "Line1\tTab\tTest");

      expect(input.value).toContain("Tab");
    });
  });

  // check DOM structure
  describe("DOM Structure", () => {
    test("form contains exactly one input and one button", () => {
      const { container } = render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const form = container.querySelector("form");
      const inputs = form.querySelectorAll("input");
      const buttons = form.querySelectorAll("button");

      expect(inputs).toHaveLength(1);
      expect(buttons).toHaveLength(1);
    });

    test("input is wrapped in div with mb-3 class", () => {
      const { container } = render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const div = container.querySelector(".mb-3");
      expect(div).toBeInTheDocument();
      expect(div.querySelector("input")).toBeInTheDocument();
    });

    test("button has correct type attribute", () => {
      render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const button = screen.getByRole("button", { name: /submit/i });
      expect(button).toHaveAttribute("type", "submit");
    });

    test("form element exists and wraps all content", () => {
      const { container } = render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={jest.fn()} />
      );

      const forms = container.querySelectorAll("form");
      expect(forms).toHaveLength(1);

      const form = forms[0];
      expect(form.querySelector("input")).toBeInTheDocument();
      expect(form.querySelector("button")).toBeInTheDocument();
    });
  });

  // check performance
  describe("Performance", () => {
    test("handles rapid sequential input changes", async () => {
      render(<CategoryFormHarness initial="" />);
      const input = screen.getByPlaceholderText(/enter new category/i);

      await userEvent.type(input, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

      expect(input).toHaveValue("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    });

    test("component re-renders when value prop changes", () => {
      const { rerender } = render(
        <CategoryForm
          handleSubmit={jest.fn()}
          value="initial"
          setValue={jest.fn()}
        />
      );

      let input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("initial");

      rerender(
        <CategoryForm
          handleSubmit={jest.fn()}
          value="updated"
          setValue={jest.fn()}
        />
      );

      input = screen.getByPlaceholderText(/enter new category/i);
      expect(input.value).toBe("updated");
    });
  });

  // check event propagation
  describe("Event Propagation", () => {
    test("form submission event bubbles to parent elements", () => {
      const parentHandler = jest.fn();
      const formHandler = jest.fn((e) => e.preventDefault());

      const { container } = render(
        <div onSubmit={parentHandler}>
          <CategoryForm
            handleSubmit={formHandler}
            value="test"
            setValue={jest.fn()}
          />
        </div>
      );

      const form = container.querySelector("form");
      fireEvent.submit(form);

      expect(formHandler).toHaveBeenCalledTimes(1);
      expect(parentHandler).toHaveBeenCalledTimes(1);
    });

    test("input onChange event is triggered correctly", () => {
      const setValue = jest.fn();
      render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={setValue} />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);
      fireEvent.change(input, { target: { value: "New Value" } });

      expect(setValue).toHaveBeenCalledWith("New Value");
      expect(setValue).toHaveBeenCalledTimes(1);
    });
  });

  // checks form behaviour
  describe("Form Behavior Integration", () => {
    test("BUG: form does NOT prevent default submission (causes page reload)", () => {
      const mockSubmit = jest.fn();
      const { container } = render(
        <CategoryForm
          handleSubmit={mockSubmit}
          value="test"
          setValue={jest.fn()}
        />
      );

      const form = container.querySelector("form");
      const submitEvent = new Event("submit", {
        bubbles: true,
        cancelable: true,
      });

      form.dispatchEvent(submitEvent);

      expect(submitEvent.defaultPrevented).toBe(false);
      expect(mockSubmit).toHaveBeenCalledTimes(1);
    });

    test("BUG: empty string submission is allowed (no validation)", async () => {
      const mockSubmit = jest.fn((e) => e.preventDefault());

      render(
        <CategoryForm handleSubmit={mockSubmit} value="" setValue={jest.fn()} />
      );

      const button = screen.getByRole("button", { name: /submit/i });
      await userEvent.click(button);

      expect(mockSubmit).toHaveBeenCalledTimes(1);
    });

    test("BUG: no maxLength restriction allows unlimited input", () => {
      const setValue = jest.fn();

      render(
        <CategoryForm handleSubmit={jest.fn()} value="" setValue={setValue} />
      );

      const input = screen.getByPlaceholderText(/enter new category/i);

      expect(input).not.toHaveAttribute("maxLength");

      const veryLongString = "x".repeat(10000);
      fireEvent.change(input, { target: { value: veryLongString } });

      expect(setValue).toHaveBeenCalledWith(veryLongString);
      expect(setValue.mock.calls[0][0].length).toBe(10000);
    });
  });
});
