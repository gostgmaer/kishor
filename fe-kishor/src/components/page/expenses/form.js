"use client";
import React, { useState } from "react";
import { patch, post } from "@/lib/http";
import { arrayGroupbykey } from "@/helper/function";
import { Field, FieldArray, Form, Formik, useFormik } from "formik";
import ImageUpload from "@/components/global/fields/ImageUpload";
import TaxonomyField from "@/components/global/fields/Taxanomy";
import MultiImageUploadr from "@/components/global/fields/multiImageUploadr";
import Interest from "@/components/projects/repeatable";
import { useParams, useRouter } from "next/navigation";
import Input from "@/components/global/fields/input";
import { notifySuccess } from "@/lib/notify/notice";

const ProjectForm = ({ initialValues }) => {

    const params = useParams();
    const router = useRouter();
    const id = params["id"];
    const [selectedFiles, setSelectedFiles] = useState([]);
    const [interests, setInterests] = useState([]);
    const [tags, setTags] = useState([]);
    const [imagePreview, setImagePreview] = useState('');

    const handleSave = async (values) => {
        const body = generateBody(values)
        try {
            const request = await post(`/projects`, body);
            if (request.statusCode === 201) {
                notifySuccess(request.message, 5000)
            }
        } catch (error) {

        }
    };

    const handleUpdate = async (values) => {
        const body = generateBody(values)
        try {
            const res = await patch(`/projects`, body, id);
            if (res.statusCode === 200) {
                notifySuccess(res.message, 5000)
            }
        } catch (error) {

        }
    };

    const generateBody = (values) => {
        const technology = arrayGroupbykey(interests, "category");
        return {
            ...values,
            main_image: imagePreview,
            attachments: selectedFiles,
            tags: tags,
            technologiesUsed: technology,
        };
    };

    const handleClick = (button) => {
        formik.setFieldValue("clickedButton", button);
    };

    const formik = useFormik({
        initialValues: initialValues,
        onSubmit: async (values, { setSubmitting, resetForm }) => {
            try {
                setSubmitting(true);
                switch (values["clickedButton"]) {
                    case "update":
                        handleUpdate(values);
                        break;
                    case "create":
                        handleSave(values);
                        break;
                    default:
                        break;
                }
            } catch (error) {
                console.error('Form submission error:', error);
            } finally {
                setSubmitting(false);
            }


        },
    });

    return (
        <div className="container p-2 mx-auto sm:p-4">
            <form className=" mx-auto bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4" onSubmit={formik.handleSubmit}>
                <h2 className="text-2xl mb-4 font-semibold">{id ? "Update" : "Add"} Project</h2>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    {/* Project Name */}
                    <div className="">
                        <Input label={"Project Name"} type={"text"} additionalAttrs={{ ...formik.getFieldProps('title'), placeholder: "New Project" }} classes={undefined} icon={undefined} id={"title"} />

                    </div>

                    {/* Role */}
                    <div className="">
                        <Input label={"Role"} type={"text"} additionalAttrs={{ ...formik.getFieldProps('team_role'), placeholder: "Lead Engineer Lead Developer" }} classes={undefined} icon={undefined} id={"team_role"} />

                    </div>
                    <div className="">
                        <Input label={"Repository Url"} type={"text"} additionalAttrs={{ ...formik.getFieldProps('repository'), placeholder: "Repository" }} classes={undefined} icon={undefined} id={"repository"} />

                    </div>
                    <div className="">
                        <Input label={"Live Url"} type={"text"} additionalAttrs={{ ...formik.getFieldProps('deploymentURL'), placeholder: "App Url.." }} classes={undefined} icon={undefined} id={"deploymentURL"} />

                    </div>
                    <div className="">
                        <Input label={"Start Date"} type={"date"} additionalAttrs={{ ...formik.getFieldProps('startDate'), placeholder: "MM/DD/YYYY" }} classes={undefined} icon={undefined} id={"startDate"} />

                    </div>


                </div>



                {/* Submit Button */}
                <div className="flex items-center justify-between">
                    {id ? (
                        <button
                            className=" text-white inline-flex font-medium items-center justify-center active:enabled:translate-y-px focus:outline-none focus-visible:ring-2 focus-visible:ring-opacity-50 transition-colors duration-200 px-4 py-2 text-sm h-10 rounded-md border border-transparent focus-visible:ring-offset-2 bg-gray-900 hover:enabled::bg-gray-800 active:enabled:bg-gray-1000 focus-visible:ring-gray-900/30 text-gray-0 w-max @xl:w-auto "
                            type="submit"
                            onClick={() => handleClick("update")}
                            disabled={formik.isSubmitting}
                        >
                            Update
                        </button>
                    ) : (
                        <button
                            className=" text-white inline-flex font-medium items-center justify-center active:enabled:translate-y-px focus:outline-none focus-visible:ring-2 focus-visible:ring-opacity-50 transition-colors duration-200 px-4 py-2 text-sm h-10 rounded-md border border-transparent focus-visible:ring-offset-2 bg-gray-900 hover:enabled::bg-gray-800 active:enabled:bg-gray-1000 focus-visible:ring-gray-900/30 text-gray-0 w-max @xl:w-auto "
                            type="submit"
                            onClick={() => handleClick("create")}
                            disabled={formik.isSubmitting}
                        >
                            {formik.isSubmitting ? 'Submitting...' : 'Create'}

                        </button>
                    )}
                </div>
            </form>
        </div>
    );
};

export default ProjectForm;


export const Incomeform = () => {


    return <Formik
        initialValues={{
            user: "", // Assuming userId will be filled dynamically
            incomes: [{ name: "", category: "", amount: "", description: "" }],
            expenses: [{ name: "", category: "", amount: "", description: "" }],
            savings: [{ name: "", category: "", amount: "", description: "" }],
        }}
        // validationSchema={Yup.object({
        //   // Define your validation schema here
        //   // You can set validation rules for each field
        // })}
        onSubmit={(values, { setSubmitting }) => {
            setTimeout(() => {
                alert(JSON.stringify(values, null, 2));
                setSubmitting(false);
            }, 400);
        }}
    >
        {({ values }) => (
            <Form>
                <FieldArray name="incomes">
                    {({ push, remove }) => (
                        <div>
                            <h3>Incomes</h3>
                            {values.incomes.map((income, index) => (
                                <div key={index}>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.name`}
                                                placeholder="Name"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.category`}
                                                placeholder="category"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.amount`}
                                                placeholder="amount"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.description`}
                                                placeholder="description"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>


                                    <button type="button" onClick={() => remove(index)}>
                                        Remove
                                    </button>
                                </div>
                            ))}
                            <button
                                type="button"
                                onClick={() =>
                                    push({
                                        name: "",
                                        category: "",
                                        amount: "",
                                        description: "",
                                    })
                                }
                            >
                                Add Income
                            </button>
                        </div>

                    )}
                </FieldArray>

                <button type="submit">Submit</button>
            </Form>
        )}
    </Formik>
}

export const Expensesform = () => {


    return <Formik
        initialValues={{
            user: "", // Assuming userId will be filled dynamically
            incomes: [{ name: "", category: "", amount: "", description: "" }],
            expenses: [{ name: "", category: "", amount: "", description: "" }],
            savings: [{ name: "", category: "", amount: "", description: "" }],
        }}
        // validationSchema={Yup.object({
        //   // Define your validation schema here
        //   // You can set validation rules for each field
        // })}
        onSubmit={(values, { setSubmitting }) => {
            setTimeout(() => {
                alert(JSON.stringify(values, null, 2));
                setSubmitting(false);
            }, 400);
        }}
    >
        {({ values }) => (
            <Form>
                <FieldArray name="incomes">
                    {({ push, remove }) => (
                        <div>
                            <h3>Incomes</h3>
                            {values.incomes.map((income, index) => (
                                <div key={index}>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.name`}
                                                placeholder="Name"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.category`}
                                                placeholder="category"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.amount`}
                                                placeholder="amount"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.description`}
                                                placeholder="description"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>


                                    <button type="button" onClick={() => remove(index)}>
                                        Remove
                                    </button>
                                </div>
                            ))}
                            <button
                                type="button"
                                onClick={() =>
                                    push({
                                        name: "",
                                        category: "",
                                        amount: "",
                                        description: "",
                                    })
                                }
                            >
                                Add Income
                            </button>
                        </div>

                    )}
                </FieldArray>

                <button type="submit">Submit</button>
            </Form>
        )}
    </Formik>
}
export const Savingsform = () => {

    return <Formik
        initialValues={{
            user: "", // Assuming userId will be filled dynamically
            incomes: [{ name: "", category: "", amount: "", description: "" }],
            expenses: [{ name: "", category: "", amount: "", description: "" }],
            savings: [{ name: "", category: "", amount: "", description: "" }],
        }}
        // validationSchema={Yup.object({
        //   // Define your validation schema here
        //   // You can set validation rules for each field
        // })}
        onSubmit={(values, { setSubmitting }) => {
            setTimeout(() => {
                alert(JSON.stringify(values, null, 2));
                setSubmitting(false);
            }, 400);
        }}
    >
        {({ values }) => (
            <Form>
                <FieldArray name="incomes">
                    {({ push, remove }) => (
                        <div>
                            <h3>Incomes</h3>
                            {values.incomes.map((income, index) => (
                                <div key={index}>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.name`}
                                                placeholder="Name"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.category`}
                                                placeholder="category"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.amount`}
                                                placeholder="amount"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>
                                    <div className="flex flex-col w-full">
                                        <label className=" block text-sm capitalize font-semibold  mb-1.5"></label>
                                        <div
                                            className={`flex items-center peer  w-full transition duration-200  rounded-md bg-transparent focus:ring-[0.6px] `}
                                        >
                                            <Field
                                                name={`incomes.${index}.description`}
                                                placeholder="description"
                                                className="rounded w-full  leading-tight focus:outline-none  border px-3.5 h-10 "
                                            />
                                        </div>
                                    </div>


                                    <button type="button" onClick={() => remove(index)}>
                                        Remove
                                    </button>
                                </div>
                            ))}
                            <button
                                type="button"
                                onClick={() =>
                                    push({
                                        name: "",
                                        category: "",
                                        amount: "",
                                        description: "",
                                    })
                                }
                            >
                                Add Income
                            </button>
                        </div>

                    )}
                </FieldArray>

                <button type="submit">Submit</button>
            </Form>
        )}
    </Formik>
}