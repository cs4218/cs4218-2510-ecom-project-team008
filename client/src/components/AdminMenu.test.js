import React from 'react';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from "react-router-dom";
import AdminMenu from "./AdminMenu";

describe.only('Admin Menu Component', () => {
  const renderMenu = () => {
    return render(
      <BrowserRouter>
        <AdminMenu />
      </BrowserRouter>
    )
  };

  describe('Navigation links', () => {
    beforeEach(() => {
      renderMenu();
    });

    test('renders heading Admin Panel', () => {
      expect(screen.getByText('Admin Panel')).toBeInTheDocument();
    });

    test("renders 'Create Category link with correct path", () => {
      const link = screen.getByText('Create Category');
      expect(link).toBeInTheDocument();
      expect(link.getAttribute('href')).toBe('/dashboard/admin/create-category');
    });

    test("renders 'Create Product link with correct path", () => {
      const link = screen.getByText('Create Product');
      expect(link).toBeInTheDocument();
      expect(link.getAttribute('href')).toBe('/dashboard/admin/create-product');
    });

    test("renders 'Products link with correct path", () => {
      const link = screen.getByText('Products');
      expect(link).toBeInTheDocument();
      expect(link.getAttribute('href')).toBe('/dashboard/admin/products');
    });

    test("renders 'Orders link with correct path", () => {
      const link = screen.getByText('Orders');
      expect(link).toBeInTheDocument();
      expect(link.getAttribute('href')).toBe('/dashboard/admin/orders');
    });

    test('renders links in the correct order', () => {
      const links = screen.getAllByRole('link');
      const linkTexts = links.map(link => link.textContent);
      expect(linkTexts).toEqual([
        'Create Category',
        'Create Product',
        'Products',
        'Orders'
      ]);
    });
  })
});
