import mongoose from "mongoose";

const orderSchema = new mongoose.Schema(
  {
    products: {
      type: [{ type: mongoose.ObjectId, ref: "Products" }],
      required: true,
      validate: {
        validator: function (v) {
          return Array.isArray(v) && v.length > 0;
        },
        message: "Products array must have at least one item",
      },
    },
    payment: {
      errors: {},
      params: {},
      message: {
        type: String,
        required: true,
      },
      success: {
        type: Boolean,
        required: true,
      },
    },
    buyer: {
      type: mongoose.ObjectId,
      ref: "users",
      required: true
    },
    status: {
      type: String,
      default: "Not Process",
      enum: ["Not Process", "Processing", "Shipped", "delivered", "cancel"],
      required: true
    },
  },
  { timestamps: true }
);

export default mongoose.model("Order", orderSchema);