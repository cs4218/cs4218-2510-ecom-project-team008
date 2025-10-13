import { test, expect } from '@playwright/test';
import { normalUsers } from "../config/populateDb.js";

test.describe.configure({ mode: 'serial' });

const validUserInDb = normalUsers[0];

const validUserNotInDb = {
  email: "valid_email_not_in_db@gmail.com",
  password: "valid_password_not_in_db"
};

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
    console.log(validUserInDb)
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
