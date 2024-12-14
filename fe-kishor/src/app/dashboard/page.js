import PrivateLayout from "@/components/global/layout/privateLayout";
import Tables from "@/components/page/dashboard/Tables";
import { serverMethod } from "@/lib/servermethod";


export async function generateMetadata({ params }) {
  return {
    title: "Portfolio Dashboard",
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
  // const results = await getAllRecord(props.searchParams)

  return (
    <PrivateLayout>
      <div className="text-white">
        {/* <div className=" py-4  text-4xl capitalize text-gray-900"> Dashboard</div> */}
        {/* <Tables data={results} /> */}
      </div>
    </PrivateLayout>
  );
};

export default Page;



// export const getAllRecord = async (query) => {

//   const params = {
//     method: "get",
//     header: {},
//     query: { ...query },
//   };
//   const contacts = await serverMethod(
//     `/contacts`,
//     params
//   );
//   const projects = await serverMethod(
//     `/projects`,
//     params
//   );


//   return { contacts, projects }

// }