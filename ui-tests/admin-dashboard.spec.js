/* eslint-disable notice/notice */
import { test, expect } from '@playwright/test';
import {adminUsers} from "../config/populateDb";

test.describe('Admin Dashboard', () => {
  const adminInDb = adminUsers[0];
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.getByPlaceholder('Enter Your Email').fill(adminInDb.email);
    await page.getByPlaceholder('Enter Your Password').fill(adminInDb.password);

    await page.getByRole('button', { name: 'LOGIN' }).click();

    await page.getByRole("button", { name: adminInDb.name }).click();
    await page.getByRole("link", { name: "Dashboard" }).click();
  });

  test.describe('should display admin dashboard', () => {
    test.describe('should display admin panel', () => {
      test('should display admin menu', async ({ page }) => {
        await expect(page.getByText('Admin Panel')).toBeVisible();
        await expect(page.getByRole('link', { name: 'Create Category' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Create Product' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Products' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Orders' })).toBeVisible();
      });

      test('admin panel links should be navigate correctly', async ({ page }) => {
        await page.getByRole('link', { name: 'Create Category' }).click();
        await expect(page).toHaveURL(/\/dashboard\/admin\/create-category$/);
        await page.goBack();

        await page.getByRole('link', { name: 'Create Product' }).click();
        await expect(page).toHaveURL(/\/dashboard\/admin\/create-product$/);

        await page.getByRole('link', { name: 'Products' }).click();
        await expect(page).toHaveURL(/\/dashboard\/admin\/products$/);
        await page.goBack();

        await page.getByRole('link', { name: 'Orders' }).click();
        await expect(page).toHaveURL(/\/dashboard\/admin\/orders$/);
        await page.goBack();
      });

      test('admin panel information are displayed correctly', async ({ page }) => {
        await expect(page.getByText(`Admin Name : ${adminInDb.name}`)).toBeVisible();
        await expect(page.getByText(`Admin Email : ${adminInDb.email}`)).toBeVisible();
        await expect(page.getByText(`Admin Contact : ${adminInDb.phone}`)).toBeVisible();
      });
    })
  })
});
