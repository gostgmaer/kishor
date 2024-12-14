"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAxios } from "@/lib/interceptors";
import { useAuthContext } from "@/contex/authContext";
import { useGlobalContext } from "@/contex/contextAPi";
import PasswordField from "@/components/global/fields/PasswordField";
import { signIn } from "next-auth/react";
import { notifyerror } from "@/lib/notify/notice";
import { useFormik } from "formik";
import { loginValidationSchema } from "@/util/validation/contact";
import Input from "@/components/global/fields/input";

const Login = () => {
  const { handleLoginAuth, user, userId } = useAuthContext();

  const route = useRouter();

  const formik = useFormik({
    initialValues: {
      email: "",
      password: "",
    },
    validationSchema: loginValidationSchema,
    onSubmit: async (values,{setSubmitting}) => {
      setSubmitting(true)
      const res = await signIn("credentials", {
        redirect: false,
        ...values,
      });

      if (res.ok) {
        setSubmitting(false)
        if (res.url) {
          const parsedUrl = new URL(res.url);
          const callbackUrlParam = parsedUrl.searchParams.get("callbackUrl");

          if (callbackUrlParam) {
            const decodedCallbackUrl = callbackUrlParam
              ? decodeURIComponent(callbackUrlParam)
              : "/";

            route.push(decodedCallbackUrl);
          } else {
            route.push("/dashboard");
          }

        } else {
          route.push("/home");
        }
      } else {
        setSubmitting(false)
        notifyerror(res.error, 5000)
      }
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="bg-white p-8 rounded-lg shadow-md w-96 text-black">
        <h2 className="text-2xl font-semibold mb-4">Login</h2>
        <form onSubmit={formik.handleSubmit} action="post">
          <div className="mb-4 text-black">
            <label
              htmlFor="email"
              className="block text-gray-700 font-semibold"
            >
              Email
            </label>
            <input
              type="email"
              id="email"
              name="email"
              className="w-full px-4 py-2 border rounded-md focus:outline-none focus:border-blue-500"
              placeholder="Enter your email"
              {...formik.getFieldProps('email')}
            />
          </div>
          <div className="mb-4 text-black">
            <Input label={"Password"} type={"password"} additionalAttrs={{
              ...formik.getFieldProps("password"),
              placeholder: "Password",
            }} classes={undefined} icon={undefined} id={"password"} />
          </div>
          <div className="mb-4 mt-10">
            <button
              type="submit"
              disabled={formik.isSubmitting}
              className="w-full bg-blue-500 disabled:bg-blue-200  text-white font-semibold py-2 rounded-md hover:bg-blue-600 focus:outline-none focus:bg-blue-600"
            >
              Login
            </button>
          </div>
        </form>
        <p className=" text-end">
          {" "}
          <Link
            href={"/auth/forget-password"}
            className="text-blue-500 hover:underline"
          >
            Forget Password?
          </Link>
        </p>

      </div>

    </div>
  );
};

export default Login;
