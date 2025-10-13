import userModel from "../models/userModel.js";
import { hashPassword } from "../helpers/authHelper.js";

export const adminUsers = [
  {
    name: "Admin 1",
    email: "admin1@email.com",
    password: "password1",
    phone: "1234567890",
    address: "abc admin street 1",
    answer: "admin 1",
  },
];

export const normalUsers = [
  {
    name: "User 1",
    email: "user1@email.com",
    password: "password1",
    phone: "1234567890",
    address: "abc user street 1",
    answer: "user 1",
  },
];

export async function populate() {
  for (const admin of adminUsers) {
    console.log(admin);
    console.log(admin.name);
    await new userModel({
      name: admin.name,
      email: admin.email,
      password: await hashPassword(admin.password),
      phone: admin.phone,
      address: admin.address,
      answer: admin.answer,
      role: 1,
    }).save();
  }
  for (const user of normalUsers) {
    await new userModel({
      name: user.name,
      email: user.email,
      password: await hashPassword(user.password),
      phone: user.phone,
      address: user.address,
      answer: user.answer,
      role: 0,
    }).save();
  }
}