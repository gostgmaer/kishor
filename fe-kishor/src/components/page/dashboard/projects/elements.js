"use client"
import CurrentTable from '@/components/elements/component/Table';

import { del } from '@/lib/http';
import ProjectsServices from '@/lib/services/Project';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import React, { useEffect, useState } from 'react'
import { FaEye, FaTrash,FaEdit } from 'react-icons/fa';

export const ProjectTable = (props) => {




    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10); // Default items per page
    const [data, setData] = useState(null);
    const route = useRouter()




    const handleDelete = async (id) => {
        const req = await del(`/projects`, id);
        if (req.statusCode === 200) {
            loadprojects()
        }
    };

    const loadprojects = async () => {
        const query = {
            limit: itemsPerPage,
            page: currentPage,
        };

        const fetch = await ProjectsServices.getProjects(query)
        setData(fetch)

    };

    useEffect(() => {
        loadprojects();
    }, [currentPage, itemsPerPage]);





    const columns = [
        {
          title: "Title",
          dataIndex: "title",
          key: "title",
        },
       
        {
          title: "is FullStack",
          dataIndex: "fullstack",
          key: "fullstack",
        },
        {
          title: "UI URL",
          dataIndex: "ui_url",
          key: "ui_url",
         
        },
   
        {
          title: "Status",
          dataIndex: "current_status",
          key: "current_status",
          sorter: (a, b) => a.status - b.status,
          render: (index, item) => (
            <span className={` capitalize `}>
              {item.status}
            </span>
          ),
        },
    
        {
          title: (
            <div className="flex items-center gap-1 opacity-0">
              <div>Actions</div>
            </div>
          ),
          key: "actions",
          render: (index, item) => (
            <div className="flex items-center justify-end gap-3 pe-4">
              <Link
                href={`/dashboard/projects/${item._id}/edit`}
                className="px-3 py-1 bg-emerald-100 text-xs text-emerald-600 hover:bg-emerald-500 hover:text-white transition-all font-semibold rounded-full"
              >
                <FaEdit />
              </Link>
              <Link
                href={`/dashboard/projects/${item._id}`}
                className="px-3 py-1 bg-emerald-100 text-xs text-emerald-600 hover:bg-emerald-500 hover:text-white transition-all font-semibold rounded-full"
              >
                <FaEye />
              </Link>
           
              <label
        
                className="px-3 py-1 bg-emerald-100 text-xs text-emerald-600 hover:bg-emerald-500 hover:text-white transition-all font-semibold rounded-full"
              >
                <FaTrash />
              </label>
      
            </div>
          ),
        },
      ];

    // const buttons = [
    //     {
    //         label: <MdEdit className=" w-5 h-5" />,
    //         onClick: (property) => {
    //             route.push(`/dashboard/projects/${property._id}/edit`);
    //         },
    //     },
       

    // ];



    return (
        <div>
            <div className="container p-2 mx-auto sm:p-4 dark:text-gray-100">
                <div className="overflow-x-auto w-full  py-4 text-md  text-black text-right">
                    <Link href={'/dashboard/projects/create'}
                        // onClick={() => setOpen(!open)}
                        className="bg-gray-600 hover:bg-gray-800 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    >

                        Add project
                    </Link>
                </div>
                <div className="overflow-x-auto">

            

                    <CurrentTable
                        data={data?.result}
                        tableColumn={columns}
                        pagination={{
                            total: data?.total_record,
                            page: currentPage,
                            limit: itemsPerPage,
                            setPage: setCurrentPage,
                            setLimit: setItemsPerPage,
                        }}
                        checked={false}
                    />


                </div>
            </div>
         

        </div>
    )
}

