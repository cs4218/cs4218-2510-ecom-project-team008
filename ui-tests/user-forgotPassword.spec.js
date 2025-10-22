import { test, expect } from '@playwright/test';
import { normalUsers } from "../config/populateDb.js";
import { clearAndRepopulateDB } from "../config/db";

test.describe.configure({ mode: 'serial' });

const validUserInDb = normalUsers[0];

const validResetInfo = {
  email: validUserInDb.email,
  password: "new_password_123",
  answer: validUserInDb.answer
};

const invalidResetInfo = {
  email: "invalid_user@email.com",
  password: "password",
  answer: "wrong_answer"
};

test.beforeEach(async ({ page }) => {
  await clearAndRepopulateDB();
  await page.goto('./forgot-password');
});

test.describe('Forgot Password Page UI', () => {
  test('should display all input fields and buttons', async ({ page }) => {
    await expect(page.getByText('RESET PASSWORD FORM')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Email')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your New Password')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Security Answer')).toBeVisible();
    await expect(page.getByRole('button', { name: 'RESET PASSWORD' })).toBeVisible();
  });

  test('should keep password field masked while typing', async ({ page }) => {
    const passwordField = page.getByPlaceholder('Enter Your New Password');
    await expect(passwordField).toHaveAttribute('type', 'password');

    await passwordField.fill(validResetInfo.password);
    const value = await passwordField.inputValue();
    expect(value).toBe(validResetInfo.password);
  });
});

test.describe('Forgot Password Functionality', () => {
  test('should fill form and reset password successfully', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Email').fill(validResetInfo.email);
    await page.getByPlaceholder('Enter Your New Password').fill(validResetInfo.password);
    await page.getByPlaceholder('Enter Your Security Answer').fill(validResetInfo.answer);

    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page.getByText(/password reset successful/i)).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/login$/);
  });

  test('should show error for invalid answer', async ({ page }) => {
    await page.route('**/api/v1/auth/forgot-password', route => {
      route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          success: false,
          message: 'Invalid security answer',
        }),
      });
    });

    await page.getByPlaceholder('Enter Your Email').fill(validResetInfo.email);
    await page.getByPlaceholder('Enter Your New Password').fill(validResetInfo.password);
    await page.getByPlaceholder('Enter Your Security Answer').fill('wrong_answer');
    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page.getByText(/Invalid security answer/i)).toBeVisible();
    await expect(page).toHaveURL(/\/forgot-password$/);
  });

  test('should show generic error toast on server failure', async ({ page }) => {
    await page.route('**/api/v1/auth/forgot-password', route => route.abort('failed'));

    await page.getByPlaceholder('Enter Your Email').fill(invalidResetInfo.email);
    await page.getByPlaceholder('Enter Your New Password').fill(invalidResetInfo.password);
    await page.getByPlaceholder('Enter Your Security Answer').fill(invalidResetInfo.answer);

    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page.getByText(/Something went wrong/i)).toBeVisible();
  });

  test('should not navigate away when email is missing', async ({ page }) => {
    await page.getByPlaceholder('Enter Your New Password').fill(validResetInfo.password);
    await page.getByPlaceholder('Enter Your Security Answer').fill(validResetInfo.answer);
    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page).toHaveURL(/\/forgot-password$/);
  });

  test('should not navigate away when password is missing', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Email').fill(validResetInfo.email);
    await page.getByPlaceholder('Enter Your Security Answer').fill(validResetInfo.answer);
    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page).toHaveURL(/\/forgot-password$/);
  });

  test('should not navigate away when security answer is missing', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Email').fill(validResetInfo.email);
    await page.getByPlaceholder('Enter Your New Password').fill(validResetInfo.password);
    await page.getByRole('button', { name: 'RESET PASSWORD' }).click();

    await expect(page).toHaveURL(/\/forgot-password$/);
  });
});
