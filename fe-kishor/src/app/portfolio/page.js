import PageLayout from "@/components/global/layout/pageLayout";
import { PortfolioBlock } from "@/components/projects/elements";
// import { serverMethod } from "@/lib/servermethod";
import ProjectsServices from "@/lib/services/Project";
import Head from "next/head";

export async function generateMetadata({ params }) {
  return {
    title: "Kishor Sarkar Portfolio",
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

const Index = async (props) => {
  // const projects = await getAllRecord(props.searchParams)
  // console.log("projects",projects);
  const projects = await ProjectsServices.getProjects(props.searchParams)

  // console.log(projects);
  
  
  return (
    <PageLayout>
      <Head>
        <title>Kishor Sarkar Portfolio</title>
      </Head>

      <PortfolioBlock projects={projects} />
    </PageLayout>
  );
};

export default Index;


// export const getAllRecord = async (query) => {
//   const fetch = await ProjectsServices.getProjects(query)
//   return fetch

// }