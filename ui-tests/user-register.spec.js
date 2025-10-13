import { test, expect } from '@playwright/test';

test.describe.configure({ mode: 'parallel' });

test.beforeEach(async ({ page }) => {
  await page.goto('./register');
});

const validUser = {
  name: "valid name",
  email: "valid_email@gmail.com",
  password: "valid_password",
  phone: "99898233",
  address: "valid_address",
  dob: "2000-05-05",
  sport: "table tennis"
}

test.describe('Register new user', () => {
  test('should display all headers, input fields and button', async ({ page }) => {
    await expect(page.getByText('REGISTER FORM')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Name')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Email')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Password')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Phone')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your Address')).toBeVisible();
    await expect(page.getByPlaceholder('Enter Your DOB')).toBeVisible();
    await expect(page.getByPlaceholder('What is Your Favorite sports')).toBeVisible();
    await expect(page.getByRole('button', { name: 'REGISTER' })).toBeVisible();
  });

  test('should fill the form and register successfully', async ({ page }) => {
    await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
    await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
    await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
    await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
    await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
    await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
    await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

    await page.getByRole("button", { name: "REGISTER" }).click();

    await expect(page.getByText("Register Successfully, please login")).toBeVisible();
    await expect(page).toHaveURL(/.*\/login/);
  });

  test.describe('Form validations', () => {
    test.describe('should not navigate to login when a field is missing', () => {

      test('should not navigate away when name is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when email is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when password is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when phone is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when address is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when DOB is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away when sports is missing because validation failed', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away for invalid email format', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill("invalid_email");
        await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
      });

      test('should not navigate away and display error for passwords shorter than 6', async ({ page }) => {
        await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
        await page.getByPlaceholder('Enter Your Email').fill(validUser.email);
        await page.getByPlaceholder('Enter Your Password').fill("1");
        await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
        await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
        await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
        await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);

        await page.getByRole("button", { name: "REGISTER" }).click();

        await page.waitForTimeout(500);
        await expect(page).toHaveURL(/.*\/register/);
        await expect(page.getByText("Password must be at least 6 characters")).toBeVisible();
      });
    });

    test('should hide password characters while typing', async ({ page }) => {
      const passwordField = page.getByPlaceholder('Enter Your Password');

      await expect(passwordField).toHaveAttribute('type', 'password');

      await passwordField.fill(validUser.password);

      const value = await passwordField.inputValue();
      expect(value).toBe(validUser.password);
    });
  });

  test.describe('User already exists', () => {
    test('should show error when trying to register with existing email', async ({ page }) => {
      // First registration
      await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
      await page.getByPlaceholder('Enter Your Email').fill("existing_email@gmail.com");
      await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
      await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
      await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
      await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
      await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);
      await page.getByRole('button', { name: 'REGISTER' }).click();

      // Second registration
      await page.goto('/register');
      await page.getByPlaceholder('Enter Your Name').fill(validUser.name);
      await page.getByPlaceholder('Enter Your Email').fill("existing_email@gmail.com");
      await page.getByPlaceholder('Enter Your Password').fill(validUser.password);
      await page.getByPlaceholder('Enter Your Phone').fill(validUser.phone);
      await page.getByPlaceholder('Enter Your Address').fill(validUser.address);
      await page.getByPlaceholder('Enter Your DOB').fill(validUser.dob);
      await page.getByPlaceholder('What is Your Favorite sports').fill(validUser.sport);
      await page.getByRole('button', { name: 'REGISTER' }).click();

      await expect(page.getByText('Already Register please login')).toBeVisible();
      await expect(page).toHaveURL(/\/register$/);
    });
  })
});
