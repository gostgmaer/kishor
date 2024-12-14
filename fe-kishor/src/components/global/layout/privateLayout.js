
"use client"
import React from "react";
import Header from "../navbar/private/header";
import { handler } from "@/app/api/auth/[...nextauth]/route";
import Link from "next/link";
import { getServerSession } from "next-auth/next";
const PrivateLayout = async ({ children }) => {
  const session = true

  if (!session) {
    return (

      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-4xl font-bold text-red-500">403 Forbidden</h1>
          <p className="mt-4 text-gray-600">
            You do not have permission to access this page.
          </p>
          <Link href={`/auth/login`}>
            Login
          </Link>
        </div>
      </div>


    );
  } else {
    return (
      <div className="print:px-0 bg-white min-h-screen">
        <Header />
        <div className="mx-auto max-w-7xl py-6 sm:px-6 lg:px-8">{children}</div>
      </div>
    );
  }


};

export default PrivateLayout;
