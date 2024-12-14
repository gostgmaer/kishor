"use client";
import Pagination from "@/components/global/pagination/Pagination";
import { get } from "@/lib/http";
import moment from "moment";
import Link from "next/link";
import React, { useEffect, useState } from "react";
import { FaEye } from "react-icons/fa";
import { useRouter } from "next/navigation";

const Tables = (props) => {
  const route = useRouter();


  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      <div className=" col-span-1">
        <ProjectContacts />
      </div>
      <div className=" col-span-1">
        <ContactsTable />
      </div>
    </div>
  );
};

export default Tables;

const ContactsTable = () => {
  const [contact, setContact] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(5); // Default items per page
  const [totalPages, setTotalPages] = useState(100);

  const queryPrams = {
    limit: itemsPerPage,
    page: currentPage,
  };

  const loadContacts = async () => {
    // Handle form submission here, e.g., send data to an API
    // `/record/${appId}/container/${contactContiner}`,
    const req = await get(`/contacts`, queryPrams);
    setContact(req.result);
    setTotalPages(
      req.total / itemsPerPage < 1 ? 1 : Math.ceil(req.total / itemsPerPage)
    );
  };

  useEffect(() => {
    loadContacts();
  }, [currentPage, itemsPerPage]);

  return (
    <div className="container mx-auto rounded dark:text-gray-100 capitalize">
      <div className=" bg-gray-900 py-2 px-4"> latest Contacts</div>
      <div className="overflow-x-auto">
        <table className="w-full p-6 text-xs text-left ">
          <thead>
            <tr className=" bg-gray-700">
              <th scope="col" className="px-6 py-3">
                Name
              </th>
              <th scope="col" className="px-6 py-3">
                Email
              </th>
              <th scope="col" className="px-6 py-3">
                Phone
              </th>

              <th scope="col" className="px-6 py-3">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="border-b bg-gray-900 border-gray-700">
            {contact.map((item, index) => (
              <tr
                key={index}
                className="bg-white border-b dark:bg-gray-800 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                <th
                  scope="row"
                  className="px-6 py-2 font-medium text-gray-900 whitespace-nowrap dark:text-white"
                >
                  {item.firstName} {item.lastName}
                </th>
                <td className="px-6 py-2">
                  <Link href={`mailto:${item.email}`}>{item.email}</Link>
                </td>
                <td className="px-6 py-2">
                  <Link href={`tel:${item.country}${item.contactNumber}`}>
                    {item.country}
                    {item.contactNumber}
                  </Link>
                </td>

                <td className="px-6 py-2 flex justify-end gap-3">
                  <Link
                    href={`/dashboard/contacts/${item._id}`}
                    className="text-gray-400 hover:text-gray-100 p-2 border rounded-full mr-2"
                  >
                    <FaEye />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot className="w-full"></tfoot>
        </table>
        {!contact.length && (
          <div className="bg-gray-900 text-white px-auto capitalize text-center py-40">
            no content found{" "}
          </div>
        )}
        <div className="bg-gray-700 text-white px-4 py-2">
          <Pagination
            endpoint={"/contact"}
            items={[5, 10, 15, 30, 50, 100]}
            pages={2000}
            setData={setContact}
            currentPage={currentPage}
            setCurrentPage={setCurrentPage}
            itemsPerPage={itemsPerPage}
            setItemsPerPage={setItemsPerPage}
            totalPages={totalPages}
            setTotalPages={setTotalPages}
          />
        </div>
      </div>
    </div>
  );
};

// import ReactQuill from "react-quill";

const ProjectContacts = () => {
  const [contact, setContact] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(5); // Default items per page
  const [totalPages, setTotalPages] = useState(100);
  const [id, setId] = useState(undefined);
  const [open, setOpen] = useState(false);

  const queryPrams = {
    limit: itemsPerPage,
    page: currentPage,
  };

  const loadContacts = async () => {
    const req = await get(
      `/projects`,
      queryPrams
    );
    console.log(req);
    setContact(req.result);
    setTotalPages(
      req.total / itemsPerPage < 1
        ? 1
        : Math.ceil(req.total_record / itemsPerPage)
    );
  };

  useEffect(() => {
    loadContacts();
  }, [currentPage, itemsPerPage]);

  return (
    <div className="container  mx-auto rounded  dark:text-gray-100 capitalize">
      <div className=" bg-gray-900 py-2 px-4"> latest Projects</div>
      <div className="overflow-x-auto">
        <table className="w-full p-6 text-xs text-left ">
          <thead>
            <tr className=" bg-gray-700">
              <th scope="col" className="px-6 py-3">
                Name
              </th>

              <th scope="col" className="px-6 py-3">
                Start Time
              </th>
              <th scope="col" className="px-6 py-3">
                End Time
              </th>
              <th scope="col" className="px-6 py-3 text-end">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="border-b bg-gray-900 border-gray-700">
            {contact.map((item, index) => (
              <tr
                key={index}
                className="bg-white border-b dark:bg-gray-800 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                <th
                  scope="row"
                  className="px-6 py-2 flex gap-3 items-center font-medium text-gray-900 whitespace-nowrap dark:text-white"
                >
                  {/* <Image
                  src={item.main_image}
                  width={40}
                  className="h-8 w-8"
                  height={40}
                  alt={item.name}
                ></Image> */}
                  {item.name}
                </th>

                <td className="px-6 py-2">
                  {moment(item.start_date).format("D MMM yyyy")}
                </td>
                <td className="px-6 py-2">
                  {moment(item.end_date).format("D MMM yyyy")}
                </td>
                <td className="px-6 py-2 flex justify-end gap-3">
                  <Link
                    href={`/dashboard/projects/${item._id}`}
                    className="text-gray-400 hover:text-gray-100 p-2 border rounded-full"
                  >
                    <FaEye />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot className="w-full"></tfoot>
        </table>
        {!contact.length && (
          <div className="bg-gray-900 text-white px-auto capitalize text-center py-40">
            no content found{" "}
          </div>
        )}
        <div className="bg-gray-700 text-white px-4 py-2">
          <Pagination
            endpoint={"/contact"}
            items={[5, 10, 15, 30, 50, 100]}
            pages={2000}
            setData={setContact}
            currentPage={currentPage}
            setCurrentPage={setCurrentPage}
            itemsPerPage={itemsPerPage}
            setItemsPerPage={setItemsPerPage}
            totalPages={totalPages}
            setTotalPages={setTotalPages}
          />
        </div>
      </div>
    </div>
  );
};
