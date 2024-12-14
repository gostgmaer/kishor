import PrivateLayout from "@/components/global/layout/privateLayout";
import { serverMethod } from "@/lib/servermethod";
import { ProjectTable } from "@/components/page/dashboard/projects/elements";


export async function generateMetadata({ params }) {
  return {
    title: "Portfolios",
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




const Page = async (props) => {

  const projects = await getAllRecord(props.searchParams)

  return (
    <>
      <PrivateLayout>
        <ProjectTable data={projects} />
      </PrivateLayout>
    </>
  );
};

export default Page;



export const getAllRecord = async (query) => {

  const params = {
    method: "get",
    header: {},
    query: { ...query },
  };
  const projects = await serverMethod(
    `/projects`,
    params
  );


  return projects

}