/* eslint-disable notice/notice */
import { test, expect } from '@playwright/test';
import axios from "axios";

test.describe.configure({ mode: 'serial' });

const validUserInDb = {
  name: "Test User",
  email: "testuser@gmail.com",
  password: "password123",
  phone: "91234567",
  address: "123 Playwright St",
  DOB: "2000-05-05",
  answer: "table tennis"
};

const validUserNotInDb = {
  email: "valid_email_not_in_db@gmail.com",
  password: "valid_password_not_in_db"
};

test.beforeAll(async () => {
  const res = await axios.post('http://localhost:6060/api/v1/auth/register', {
    name: validUserInDb.name,
    email: validUserInDb.email,
    password: validUserInDb.password,
    phone: validUserInDb.phone,
    address: validUserInDb.address,
    DOB: validUserInDb.DOB,
    answer: validUserInDb.answer
  });
});

test.beforeEach(async ({ page }) => {
  await page.goto('./login');
});

test.describe('Login Page UI', () => {
  test('should display all inputs and buttons', async ({ page }) => {
    await expect(page.getByText('LOGIN FORM')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Email')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Forgot Password' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'LOGIN' })).toBeVisible();
  });
});

test.describe('Login Functionality', () => {
  test('should fill the form and login successfully', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Email').fill(validUserInDb.email);
    await page.getByPlaceholder('Enter Your Password').fill(validUserInDb.password);

    await page.getByRole('button', { name: 'LOGIN' }).click();

    await expect(page.getByText(/login successfully/i)).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/$/);
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route => {
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, message: 'Invalid Password' })
      });
    });

    await page.getByPlaceholder('Enter Your Email').fill(validUserNotInDb.email);
    await page.getByPlaceholder('Enter Your Password').fill('wrong_password');

    await page.getByRole('button', { name: 'LOGIN' }).click();

    await expect(page.getByText(/Invalid Password/i)).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('should not navigate away when email is missing', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Password').fill(validUserInDb.password);
    await page.getByRole('button', { name: 'LOGIN' }).click();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('should not navigate away when password is missing', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Email').fill(validUserInDb.email);
    await page.getByRole('button', { name: 'LOGIN' }).click();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('should hide password characters while typing', async ({ page }) => {
    const passwordField = page.getByPlaceholder('Enter Your Password');
    await expect(passwordField).toHaveAttribute('type', 'password');

    await passwordField.fill(validUserInDb.password);
    const value = await passwordField.inputValue();
    expect(value).toBe(validUserInDb.password);
  });

  test('should navigate to forgot password page when clicking button', async ({ page }) => {
    await page.getByRole('button', { name: 'Forgot Password' }).click();
    await expect(page).toHaveURL(/\/forgot-password$/);
  });

  test('should show generic error toast on server failure', async ({ page }) => {
    await page.route('**/api/v1/auth/login', route => route.abort('failed'));

    await page.getByPlaceholder('Enter Your Email').fill(validUserNotInDb.email);
    await page.getByPlaceholder('Enter Your Password').fill(validUserNotInDb.password);
    await page.getByRole('button', { name: 'LOGIN' }).click();

    await expect(page.getByText(/Something went wrong/i)).toBeVisible();
  });
});
