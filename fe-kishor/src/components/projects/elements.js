"use client"
import Image from "next/image";
import Link from "next/link";
import PaginationBlock from "../global/pagination/paginationBlock";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { generateUrlFromNestedObject } from "@/helper/function";
import ProjectsServices from "@/lib/services/Project";
import { Card, Skeleton } from "@nextui-org/react";




export const PortfolioBlock = (props) => {
  const  { projects} = props
    const route = useRouter()
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10);
    const loadprojects = async () => {
        const query = {
            limit: itemsPerPage,
            page: currentPage,
        };
        const checkQuerydata = generateUrlFromNestedObject({ ...query });
        route.push(`/portfolio${checkQuerydata}`);
    };

    useEffect(() => {
        loadprojects();
    }, [currentPage, itemsPerPage]);


    return (
        <div className="rounded-[20px] my-5 py-10 gap-10 pb-0  shadow-md m-auto bg-gray-100 flex items-center justify-center flex-col w-full ">
            <div className=" grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 justify-center w-full px-10 ">

                <div>
                    { }
                </div>


                {projects ? projects?.result?.map((project, index) => (
                    <Project key={index} project={project} />
                )) : Array.from(Array(10).keys()).map(item => (<Card key={item} className="w-[200px] space-y-5 p-4" radius="lg">
                    <Skeleton className="rounded-lg">
                        <div className="h-24 rounded-lg bg-secondary"></div>
                    </Skeleton>
                    <div className="space-y-3">
                        <Skeleton className="w-3/5 rounded-lg">
                            <div className="h-3 w-full rounded-lg bg-secondary"></div>
                        </Skeleton>
                        <Skeleton className="w-4/5 rounded-lg">
                            <div className="h-3 w-full rounded-lg bg-secondary-300"></div>
                        </Skeleton>
                        <Skeleton className="w-2/5 rounded-lg">
                            <div className="h-3 w-full rounded-lg bg-secondary-200"></div>
                        </Skeleton>
                    </div>
                </Card>))}
            </div>
            <div className="bg-gray-700 text-white py-1 w-full">
                <PaginationBlock totalItems={projects?.total_record} limit={itemsPerPage} currentPage={currentPage} onPageChange={setCurrentPage} onItemsPerPageChange={setItemsPerPage} />
            </div>
        </div>
    )
}


export const Project = ({ project }) => {
    return (
        <Link href={`/portfolio/${project._id}`} className="">
            <div className="bg-white shadow-lg rounded-lg overflow-hidden transform transition-transform hover:scale-105">
                <Image
                    src={project?.main_image}
                    alt={project.name}
                    width={176}
                    height={320}
                    className="w-full h-auto object-cover max-h-44"
                />

                <div className="p-4">
                    <h2 className="text-2xl font-semibold mb-2">{project.title}</h2>
                    {/* {project?.summery && <p className="text-gray-600 mb-4">
                        {project?.summery?.substring(0, 140) + '...'}
                    </p>} */}

                    {/* <div className="flex  flex-wrap gap-2 mb-4 justify-start">
                        {project.tags.splice(0, 4).map((tag, index) => (
                            <span
                                key={index}
                                className="bg-blue-500 text-white px-4 py-1 rounded"
                            >
                                {tag}
                            </span>
                        ))}
                    </div> */}
                    {/* 
                    <div className="grid grid-cols-2 gap-2 text-gray-600 mb-4"></div> */}
                </div>
            </div>
        </Link>
    );
};
