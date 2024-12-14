"use client";
import PrivateLayout from "@/components/global/layout/privateLayout";
import Technologies from "@/components/projects/technologi";
import { getsingle } from "@/lib/http";
import { useAxios } from "@/lib/interceptors";
import Image from "next/image";
import { useParams } from "next/navigation";
import React, { useEffect, useState } from "react";

// export async function generateMetadata(props) {
//   return {
//     title: "Portfolio Details",
//     description: "Full stack web developer",
//     openGraph: {
//       type: "website",
//       url: "l",
//       title: "My Website",
//       description: "My Website Description",
//       siteName: "My Website",
//       images: [
//         {
//           url: "https://example.com/og.png",
//         },
//       ],
//     },
//   };
// }


const Page = () => {
  const [contact, setContact] = useState(undefined);
  const [axios, spinner] = useAxios();
  const param = useParams();
  const id = param.id;

  const getSingleproject = async (params) => {
    const req = await getsingle(`/projects`, id);
    setContact(req.result);
  };

  useEffect(() => {
    getSingleproject();
  }, [id]);

  const p = {
    name: "project1",
    startDate: null,
    endDate: null,
    description: "descrpias",
    highlights: [""],
    url: "deploy",
    repository: "repo",
    overview: "overview",
    _id: "6522e14d0c9a8a475d5fe302",
  };
  return (
    <>
      <PrivateLayout>
        <div className="bg-white shadow-md  rounded-lg w-full">
          <ProjectCard project={contact} />
        </div>

        {spinner}
      </PrivateLayout>
    </>
  );
};

export default Page;

// components/ProjectCard.js
const ProjectCard = ({ project }) => {
  return (
    <div className="bg-white shadow-lg rounded-lg overflow-hidden">
      <Image
        src={project?.main_image}
        alt={project?.name}
        width={500000}
        height={100000}
        className="w-full h-auto object-cover"
      />
      <div className="p-6">
        <h1 className="text-2xl font-semibold mb-4">{project?.name}</h1>
        {/* <p className="text-gray-600 text-lg mb-4">{project?.intro}</p> */}
        <div
          className="text-gray-600 text-lg mb-4"
          dangerouslySetInnerHTML={{ __html: project?.overview }}
        />
        <div className="grid grid-cols-1 gap-4 p-5">
          <div>
            <h2 className="text-xl font-semibold">Technologies Used:</h2>
            <Technologies />
          </div>
        </div>
        <div className="grid grid-cols-1 gap-4 p-5">
          {
            <div>
              <h2 className="text-xl font-semibold">tags:</h2>
              <ul className=" flex justify-start gap-2">
                {project?.tags?.map((item, index) => (
                  <li key={index} className="text-gray-600">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          }
        </div>
        <div className="grid grid-cols-1 gap-4 p-5">
          {
            <div>
              <h2 className="text-xl font-semibold">Team Members:</h2>
              <ul className="list-disc pl-4">
                {project?.team?.map((member, index) => (
                  <li key={index} className="text-gray-600">
                    <a
                      className="text-blue-500 hover:underline"
                      href={member.url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {member.name}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          }
        </div>

        <div className="mt-8">
          <h2 className="text-xl font-semibold">Project Pictures:</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 mt-4">
            {project?.images.map((picture, index) => (
              <div key={index} className="relative">
                <Image
                  width={5000}
                  height={3000}
                  className="w-full h-48 object-cover rounded-lg"
                  src={picture.url}
                  alt={picture?.name}
                />
                <div className="absolute inset-0 bg-black opacity-0 hover:opacity-50 transition-opacity">
                  <p className="text-white text-center absolute inset-x-0 bottom-4">
                    {picture?.name?.substring(0, 40) + "..."}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};


