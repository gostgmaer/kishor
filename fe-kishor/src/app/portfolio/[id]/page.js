import PageLayout from "@/components/global/layout/pageLayout";
import Technologies from "@/components/projects/technologi";
import { serverMethod } from "@/lib/servermethod";
import ProjectsServices from "@/lib/services/Project";
import Head from "next/head";
import Image from "next/image";
// import { useParams } from "next/navigation";

// const getSingleData = async (id) => {

//   const params = {
//     method: "get",
//   }
//   const request = await serverMethod(`/projects/${id}`, params)
//   return request
// }

export async function generateMetadata({ params }) {
  const data = await ProjectsServices.getSingleProject(params.id)

  return {
    title: data?.result?.title,
    description: "Full stack web developer",
    openGraph: {
      type: "website",
      url: "l",
      title: "My Website",
      description: "My Website Description",
      siteName: "My Website",
      images: [
        {
          url: "https://example.com/og.png",
        },
      ],
    },
  };
}



const Page = async ({ params }) => {
  const data = await ProjectsServices.getSingleProject(params.id)
  return (
    <>

      <PageLayout>
        <div className="bg-white shadow-md rounded-lg w-full">
          <ProjectCard project={data.result} />
        </div>
      </PageLayout>
    </>
  );
};

export default Page;

const ProjectCard = ({ project }) => {
  return (
    <div className="bg-white shadow-lg rounded-lg overflow-hidden my-5">
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
      { project?.overview && <div
          className="text-gray-600 text-lg mb-4"
          dangerouslySetInnerHTML={{ __html: project?.overview }}
        />}
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
            {project?.images?.map((picture, index) => (
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
