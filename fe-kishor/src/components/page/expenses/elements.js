"use client";
import { expenseData } from "@/assets/data/mock";
import Table, { BasicTable } from "@/components/global/fields/Table";
import Input from "@/components/global/fields/input";
import ProjectForm from "@/components/projects/projectForm";
import { arraySumByKey, generateUrlFromNestedObject } from "@/helper/function";
import { del, patch, post } from "@/lib/http";
import { Field, FieldArray, Form, Formik, useFormik } from "formik";
import moment from "moment";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
import { MdDelete, MdEdit, MdPageview } from "react-icons/md";
import { v4 as uuidv4 } from 'uuid';

export const ExpenseSummery = (props) => {

    const params = useParams()

    const handleSubmit = async (second) => {
        var currentUserExpenses = JSON.parse(localStorage.getItem('currentUserExpense'));
        const req = await patch(`/expenses`, currentUserExpenses['currentData'], params.id);



    }

    return (
        <div>
            <div className=" grid grid-cols-10">
                <div className=" col-span-4">
                    <h3>Percentage of Income Spends</h3>
                    <div className="p-5">
                        <div className=" w-60 h-60 rounded-full bg-gray-500 border-10 border-green-600 flex items-center justify-center">
                            <span>8%</span>
                        </div>
                    </div>
                </div>
                <div className="col-span-6">
                    <h3>Summery</h3>
                    <div className="p-5 flex gap-2 justify-between">
                        <div className="flex flex-col gap-5">
                            <div>
                                <p className=" text-sky-600 font-medium uppercase text-sm underline">
                                    Total Monthly Income
                                </p>
                                <p className=" text-2xl">$ {arraySumByKey(expenseData.incomes, 'amount')}</p>
                            </div>
                            <div>
                                <p className=" text-sky-600 font-medium uppercase text-sm underline">
                                    Total Monthly Expenses
                                </p>
                                <p className=" text-2xl">$ {arraySumByKey(expenseData.expenses, 'amount')}</p>
                            </div>
                            <div>
                                <p className=" text-sky-600 font-medium uppercase text-sm underline">
                                    Total Monthly Savings
                                </p>
                                <p className=" text-2xl">$ {arraySumByKey(expenseData.savings, 'amount')}</p>
                            </div>
                            <div>
                                <p className=" text-sky-600 font-medium uppercase text-sm underline">
                                    Current Balance
                                </p>
                                <p className=" text-2xl">$ {arraySumByKey(expenseData.incomes, 'amount') - (arraySumByKey(expenseData.expenses, 'amount') + arraySumByKey(expenseData.savings, 'amount'))}</p>
                            </div>
                        </div>
                        <div className="income-expense-chart">
                            <div className=" w-64 h-64 rounded-full bg-gray-500 border-4 border-green-600 flex items-center justify-center">
                                <span>8%</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div className=" grid grid-cols-3 gap-2">
                <div className=" col-span-1 p-2 ">
                    <h3 className=" text-xl font-semibold my-2 ">Monthly Income</h3>
                    <div className="">
                        <IncomeTable incomes={expenseData.incomes} />

                    </div>
                </div>
                <div className="col-span-1 p-2">
                    <h3 className=" text-xl font-semibold my-2 ">Monthly Expenses</h3>
                    <div className=" ">
                        <ExpenseTable expenses={expenseData.expenses} />
                    </div>
                </div>
                <div className=" col-span-1 p-2">
                    <h3 className=" text-xl font-semibold  my-2">Monthly Savings</h3>
                    <div className="">
                        <SavingsTable savings={expenseData.savings} />
                    </div>
                </div>
            </div>
            <div className=" grid grid-cols-1 gap-2">
                <button className="px-5 py-2 bg-gray-400 border-gray-500 text-white" onClick={handleSubmit}>Update</button>
            </div>
        </div>
    );
};

export const IncomeTable = (props) => {
    const route = useRouter()
    const columns = React.useMemo(
        () => [
            //   { Header: "ID", accessor: "_id", isSortable: true },
            { Header: "Name", accessor: "name" },
            // { Header: "Category", accessor: "category" },
            { Header: "Amount", accessor: "amount" },
            {
                Header: "Date", accessor: "date",
                cell: props => moment(props.value).format('DD/MM')
            },
        ],
        []
    );

    const handleDelete = async (id) => {
        const req = await del(`/expenses/remove`, id);
        // if (req.statusCode === 200) {
        //     loadprojects()
        // }
    };
    const buttons = [
        {
            label: <MdEdit className=" w-5 h-5" />,
            onClick: (property) => {
                route.push(`/dashboard/expenses/${property._id}/edit`);
            },
        },
        // {
        //     label: <MdPageview className=" w-5 h-5" />,
        //     onClick: (property) => {
        //         route.push(`/dashboard/projects/${property._id}`);
        //     },

        // },
        {
            label: <MdDelete className=" w-5 h-5" />,
            onClick: (property) => {
                handleDelete(property._id)
            },
        },

    ];

    const formik = useFormik({
        initialValues: { name: "", category: "", amount: "", description: "", date: "" },
        onSubmit: (values) => {
            var currentUserExpenses = JSON.parse(localStorage.getItem('currentUserExpense'));
            const newExpense = { uuid: uuidv4(), ...values };
            console.log(currentUserExpenses.currentData.incomes);
            if (currentUserExpenses?.currentData.incomes) {
                currentUserExpenses['currentData']["incomes"].push(newExpense);
                localStorage.setItem('currentUserExpense', JSON.stringify(currentUserExpenses));
            } else {
                var expense = {
                    currentData: {
                        incomes: []
                    }
                }
                expense.currentData.incomes.push(newExpense)
                expense["currentData"] = { ...currentUserExpenses?.currentData, ...expense.currentData, }
                localStorage.setItem('currentUserExpense', JSON.stringify(expense));
            }

        },
    });

    return (
        <>
            <div className="sm:h-64 overflow-y-auto">
                <BasicTable
                    columns={columns}
                    data={props?.incomes}
                    buttons={buttons}
                    params={undefined}
                    ispagination={false}
                />
            </div>
            <form onSubmit={formik.handleSubmit} className="w-full  grid grid-cols-1 gap-2 py-5">
                <div><h4 className=" text-lg font-semibold  ">Add New Income</h4></div>
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('name'), placeholder: "Name" }} classes={undefined} icon={undefined} id={"name"} /></div>
                {/* <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('category') }} classes={undefined} icon={undefined} id={"category"} /></div> */}
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('amount'), placeholder: "0.00" }} classes={undefined} icon={undefined} id={"amount"} /></div>
                <div><Input label={undefined} type={'date'} additionalAttrs={{ ...formik.getFieldProps('date'), placeholder: "MM/DD/YYYY" }} classes={undefined} icon={undefined} id={"date"} /></div>
                <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    Add
                </button>
            </form>
        </>
    );
};

export const ExpenseTable = (props) => {
    const route = useRouter()
    const columns = React.useMemo(
        () => [
            //   { Header: "ID", accessor: "_id", isSortable: true },
            { Header: "Name", accessor: "name" },
            // { Header: "Category", accessor: "category" },
            { Header: "Amount", accessor: "amount" },
            { Header: "Date", accessor: "date" },
        ],
        []
    );
    const formik = useFormik({
        initialValues: { name: "", category: "", amount: "", description: "", date: "" },
        onSubmit: (values) => {
            var currentUserExpenses = JSON.parse(localStorage.getItem('currentUserExpense'));
            const newExpense = { uuid: uuidv4(), ...values };
            if (currentUserExpenses?.currentData.expenses) {
                currentUserExpenses['currentData']["expenses"].push(newExpense);
                localStorage.setItem('currentUserExpense', JSON.stringify(currentUserExpenses));
            } else {
                var expense = {
                    currentData: {
                        expenses: []
                    }
                }
                expense.currentData.expenses.push(newExpense)
                expense["currentData"] = { ...currentUserExpenses?.currentData, ...expense.currentData, }
                localStorage.setItem('currentUserExpense', JSON.stringify(expense));
            }

        },
    });
    const handleDelete = async (id) => {
        const req = await del(`/projects`, id);
        // if (req.statusCode === 200) {
        //     loadprojects()
        // }
    };
    const buttons = [
        {
            label: <MdEdit className=" w-5 h-5" />,
            onClick: (property) => {
                route.push(`/dashboard/projects/${property._id}/edit`);
            },
        },
        // {
        //     label: <MdPageview className=" w-5 h-5" />,
        //     onClick: (property) => {
        //         route.push(`/dashboard/projects/${property._id}`);
        //     },

        // },
        {
            label: <MdDelete className=" w-5 h-5" />,
            onClick: (property) => {
                handleDelete(property._id)
            },
        },

    ];
    return (
        <>    <div className="sm:h-64 overflow-y-auto">
            <BasicTable
                columns={columns}
                data={props?.expenses}
                buttons={buttons}
                params={undefined}
                ispagination={false}
            />
        </div>
            <form onSubmit={formik.handleSubmit} className="w-full  grid grid-cols-1 gap-2 py-5">
                <div><h4 className=" text-lg font-semibold  ">Add New Expenses</h4></div>
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('name'), placeholder: "Name" }} classes={undefined} icon={undefined} id={"name"} /></div>
                {/* <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('category') }} classes={undefined} icon={undefined} id={"category"} /></div> */}
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('amount'), placeholder: "0.00" }} classes={undefined} icon={undefined} id={"amount"} /></div>
                <div><Input label={undefined} type={'date'} additionalAttrs={{ ...formik.getFieldProps('date'), placeholder: "MM/DD/YYYY" }} classes={undefined} icon={undefined} id={"date"} /></div>
                <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    Add
                </button>
            </form>
        </>
    );
};


export const SavingsTable = (props) => {
    const route = useRouter()
    const columns = React.useMemo(
        () => [
            //   { Header: "ID", accessor: "_id", isSortable: true },
            { Header: "Name", accessor: "name" },
            // { Header: "Category", accessor: "category" },
            { Header: "Amount", accessor: "amount" },
            { Header: "Date", accessor: "date" },
        ],
        []
    );

    const formik = useFormik({
        initialValues: { name: "", category: "", amount: "", description: "", date: "" },
        onSubmit: (values) => {
            var currentUserExpenses = JSON.parse(localStorage.getItem('currentUserExpense'));
            const newExpense = { uuid: uuidv4(), ...values };
            if (currentUserExpenses?.currentData.savings) {
                currentUserExpenses['currentData']["savings"].push(newExpense);
                localStorage.setItem('currentUserExpense', JSON.stringify(currentUserExpenses));
            } else {
                var expense = {
                    currentData: {
                        savings: []
                    }
                }
                expense.currentData.savings.push(newExpense)
                expense["currentData"] = { ...currentUserExpenses?.currentData, ...expense.currentData, }
                localStorage.setItem('currentUserExpense', JSON.stringify(expense));
            }
        },
    });

    const handleDelete = async (id) => {
        const req = await del(`/projects`, id);
        // if (req.statusCode === 200) {
        //     loadprojects()
        // }
    };
    const buttons = [
        {
            label: <MdEdit className=" w-5 h-5" />,
            onClick: (property) => {
                route.push(`/dashboard/projects/${property._id}/edit`);
            },
        },
        // {
        //     label: <MdPageview className=" w-5 h-5" />,
        //     onClick: (property) => {
        //         route.push(`/dashboard/projects/${property._id}`);
        //     },

        // },
        {
            label: <MdDelete className=" w-5 h-5" />,
            onClick: (property) => {
                handleDelete(property._id)
            },
        },

    ];

    return (
        <>
            <div className="sm:h-64 overflow-y-auto">
                <BasicTable
                    columns={columns}
                    data={props?.savings}
                    buttons={buttons}
                    params={undefined}
                    ispagination={false}
                />
            </div>
            <form onSubmit={formik.handleSubmit} className="w-full  grid grid-cols-1 gap-2 py-5">
                <div><h4 className=" text-lg font-semibold  ">Add New Savings</h4></div>
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('name'), placeholder: "Name" }} classes={undefined} icon={undefined} id={"name"} /></div>
                {/* <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('category') }} classes={undefined} icon={undefined} id={"category"} /></div> */}
                <div><Input label={undefined} type={'text'} additionalAttrs={{ ...formik.getFieldProps('amount'), placeholder: "0.00" }} classes={undefined} icon={undefined} id={"amount"} /></div>
                <div><Input label={undefined} type={'date'} additionalAttrs={{ ...formik.getFieldProps('date'), placeholder: "MM/DD/YYYY" }} classes={undefined} icon={undefined} id={"date"} /></div>
                <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    Add
                </button>
            </form>

        </>
    );
};


export const CreateExpense = (props) => {

    const { data: session } = useSession()


    const route = useRouter()
    const formik = useFormik({
        initialValues: { name: "", month: "", },
        onSubmit: (values) => {

            handleCreate(values)


        },
    });

    const handleCreate = async (values) => {

        const body = {
            user: session.user['id'], ...values

        }
        const request = await post('/expenses/create', body)
     if (request["statusCode"]===201) {
        route.push(`/dashboard/expenses/${request["result"]["_id"]}/edit`)
     }

    }




    return <div>
        <form onSubmit={formik.handleSubmit} className="w-full  grid grid-cols-2 gap-2 py-5">
            <div className=" col-span-2"><h4 className=" text-lg font-semibold  ">Create New Expense</h4></div>
            <div><Input label={"Expense Name"} type={'text'} additionalAttrs={{ ...formik.getFieldProps('name'), placeholder: "Name" }} classes={undefined} icon={undefined} id={"name"} /></div>

            <div><Input label={"Month"} type={'date'} additionalAttrs={{ ...formik.getFieldProps('month'), placeholder: "MM/DD/YYYY" }} classes={undefined} icon={undefined} id={"month"} /></div>
            <div className=" col-span-2">
                <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                    Create
                </button>
            </div>
        </form>
    </div>

}