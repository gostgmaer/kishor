"use client";

import PrivateLayout from "@/components/global/layout/privateLayout";
import { get, patch, post } from "@/lib/http";
import React, { useEffect, useState } from "react";
import { MdEdit, MdGridView, MdPageview } from "react-icons/md";
import Table from "@/components/global/fields/Table";
import { useRouter } from "next/navigation";
import { generateUrlFromNestedObject } from "@/helper/function";
export const ContactTable = (props) => {

    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10); // Default items per page

    const route = useRouter()

    console.log(props);
    const updateIfnotActive = async (data) => {
        const res = await patch(
            `/contacts`,
            { acknoledge: !data.acknoledge },
            data._id
        );

        if (res.statusCode == 200) {
            loadContacts()
        }
    };

    const loadContacts = async () => {

        const query = {
            limit: itemsPerPage,
            page: currentPage,
        };
        const checkQuerydata = generateUrlFromNestedObject({ ...query });
        route.push(`/dashboard/contacts${checkQuerydata}`);
    };

    useEffect(() => {
        loadContacts();
    }, [currentPage, itemsPerPage]);

    const columns = React.useMemo(
        () => [

            { Header: "First Name", accessor: "firstName", },
            { Header: "Last Name", accessor: "lastName", },
            { Header: "Email Address", accessor: "email", },
            { Header: "Phone Number", accessor: "contactNumber", },
            { Header: "Company", accessor: "company", },

        ],
        []
    );
    const buttons = [
        {
            label: <MdEdit className=" w-5 h-5" />,
            onClick: (property) => {
                updateIfnotActive(property)

            },
        },
        {
            label: <MdPageview className=" w-5 h-5" />,
            onClick: (property) => {
                route.push(`/dashboard/contacts/${property._id}`);
            },
        },


    ];



    return (
        <div className="overflow-x-auto">
            <Table
                columns={columns}
                data={props?.data?.result}
                buttons={buttons}
                params={{
                    setPage: setCurrentPage,
                    setLimit: setItemsPerPage,
                    limit: itemsPerPage,
                    page: currentPage,
                    total: props?.data?.total_record,
                }} ispagination={true}               />
        </div>
    );
};

