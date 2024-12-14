
import * as Yup from "yup";

export const contactValidationSchema = Yup.object().shape({
  firstName: Yup.string().required("First Name is required"),
  lastName: Yup.string().required("last  Name is required"),
  email: Yup.string().email("Invalid email").required("Email is required"),
  message:Yup.string().required('This message is required'),
  subscribe: Yup.boolean(),
});
export const loginValidationSchema = Yup.object().shape({
  email: Yup.string()
    .email("Invalid email address")
    .required("Email is required"),
  password: Yup.string().min(8).max(12).required("Password is required"),
});
