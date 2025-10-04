import { renderHook, act } from '@testing-library/react';
import '@testing-library/jest-dom/extend-expect';
import { useSearch, SearchProvider } from "./search";

describe('useSearch', () => {
  it('should provide default values for search keyword and results correctly', () => {
    // Arrange
    const { result } = renderHook(() => useSearch(), {
      wrapper: SearchProvider
    });

    // Act
    const value = result.current[0];

    // Assert
    expect(value).toEqual({
      keyword: "",
      results: []
    });
  });

  it('should allow user to update search context correctly', () => {
    // Arrange
    const { result } = renderHook(() => useSearch(), {
      wrapper: SearchProvider
    });
    const mockValue = {
      keyword: "Mock Keyword",
      results: ["Mock Result"]
    };

    // Act
    act(() => {
      const setValue = result.current[1];
      setValue(mockValue);
    });
    const value = result.current[0];

    // Assert
    expect(value).toEqual(mockValue);
  });
});