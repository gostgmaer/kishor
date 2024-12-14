"use client"
import { Switch } from "@headlessui/react";
import { Formik, Form, Field, ErrorMessage } from "formik";
import React, { useState } from "react";
import { contactValidationSchema } from "@/util/validation/contact";
import codes from "country-calling-code";
import { get, post } from "@/lib/http";
import { useAxios } from "@/lib/interceptors";
import ContactsServices from "@/lib/services/contact";

export const ContatForm = (second) => {

    const [success, setSuccess] = useState(null);
    const [agreed, setAgreed] = useState(false);
    var countryCode = codes;
    const handleSubmit = async (values, { resetForm }) => {  
      const request = await ContactsServices.createContact(values);
      setSuccess(request);
      resetForm()
      setAgreed(false);
    };
  
    function classNames(...classes) {
      return classes.filter(Boolean).join(" ");
    }
  
    return (
      <div className="isolate bg-white px-6 py-5  rounded-lg  sm:py-5 lg:px-8">
        <div className="mx-auto  text-center">
          {success?.statusCode === 201 && "We received your contact request"}
        </div>
        <Formik
          initialValues={{
            firstName: "",
            lastName: "",
            name: "",
            email: "",
            message: "",
            contactNumber: "",
            company: "",
            country: "",
            subscribe: false,
          }}
          validationSchema={contactValidationSchema}
          onSubmit={handleSubmit}
        >
          <Form className="mx-auto mt-0 max-w-xl sm:mt-5">
            <div className="grid grid-cols-1 gap-x-8 gap-y-6 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="firstName"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  First name
                </label>
                <div className="mt-2.5">
                  <Field
                    type="text"
                    name="firstName"
                    id="firstName"
                    autoComplete="given-name"
                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <ErrorMessage
                    name="firstName"
                    component="p"
                    className="text-red-600"
                  />
                </div>
              </div>
              <div>
                <label
                  htmlFor="lastName"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  Last name
                </label>
                <div className="mt-2.5">
                  <Field
                    type="text"
                    name="lastName"
                    id="lastName"
                    autoComplete="family-name"
                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <ErrorMessage
                    name="lastName"
                    component="p"
                    className="text-red-600"
                  />
                </div>
              </div>
              <div className="">
                <label
                  htmlFor="email"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  Email
                </label>
                <div className="mt-2.5">
                  <Field
                    type="email"
                    name="email"
                    id="email"
                    autoComplete="email"
                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <ErrorMessage
                    name="email"
                    component="p"
                    className="text-red-600"
                  />
                </div>
              </div>
              <div className="">
                <label
                  htmlFor="contactNumber"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  Phone number
                </label>
                <div className="relative mt-2.5">
                  <div className="absolute inset-y-0 left-0 flex items-center">
                    <label htmlFor="country" className="sr-only">
                      Country
                    </label>
                    <Field
                      as="select"
                      id="country"
                      name="country"
                      className="h-full rounded-md border-0 bg-transparent bg-none py-0 pl-2 pr-2 text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm"
                    >
                      {countryCode.map((item) => (
                        <option key={item.country}>{item.isoCode2}</option>
                      ))}
                    </Field>
                  </div>
                  <Field
                    type="tel"
                    name="contactNumber"
                    id="contactNumber"
                    autoComplete="tel"
                    className="block w-full rounded-md border-0 px-3.5 py-2 pl-16 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                </div>
              </div>
              <div className="sm:col-span-2">
                <label
                  htmlFor="company"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  Company
                </label>
                <div className="mt-2.5">
                  <Field
                    type="text"
                    name="company"
                    id="company"
                    autoComplete="organization"
                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <ErrorMessage
                    name="company"
                    component="p"
                    className="text-red-600"
                  />
                </div>
              </div>
  
              <div className="sm:col-span-2">
                <label
                  htmlFor="message"
                  className="block text-sm font-semibold leading-6 text-gray-900"
                >
                  Message
                </label>
                <div className="mt-2.5">
                  <Field
                    name="message"
                    as="textarea"
                    id="message"
                    rows={4}
                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <ErrorMessage
                    name="message"
                    component="p"
                    className="text-red-600"
                  />
                </div>
              </div>
              <Switch.Group as="div" className="flex gap-x-4 sm:col-span-2">
                <div className="flex h-6 items-center">
                  <Switch
                    checked={agreed}
                    onChange={setAgreed}
                    name="subscribe"
                    id="subscribe"
                    className={classNames(
                      agreed ? "bg-indigo-600" : "bg-gray-200",
                      "flex w-8 flex-none cursor-pointer rounded-full p-px ring-1 ring-inset ring-gray-900/5 transition-colors duration-200 ease-in-out focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                    )}
                  >
                    <span className="sr-only">Agree to policies</span>
                    <span
                      aria-hidden="true"
                      className={classNames(
                        agreed ? "translate-x-3.5" : "translate-x-0",
                        "h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-gray-900/5 transition duration-200 ease-in-out"
                      )}
                    />
                  </Switch>
                </div>
                <Switch.Label className="text-sm leading-6 text-gray-600">
                  By selecting this, you agree to our{" "}
                  <span className="font-semibold">privacy&nbsp;policy</span>.
                </Switch.Label>
              </Switch.Group>
              <ErrorMessage
                name="subscribe"
                component="p"
                className="text-red-600"
              />
            </div>
            <div className="mt-10">
              <button
                type="submit"
                disabled={!agreed}
                className="block w-full disabled:bg-indigo-300 rounded-md bg-indigo-600 px-3.5 py-2.5 text-center text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
              >
                Let s talk
              </button>
            </div>
          </Form>
        </Formik>
     
      </div>
    );
  };
  