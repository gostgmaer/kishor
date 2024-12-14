
import PrivateLayout from "@/components/global/layout/privateLayout";
import { serverMethod } from "@/lib/servermethod";
import { ContactTable } from "@/components/page/dashboard/contacts/elements";

const Page = async (props) => {
  const results = await getAllRecord(props.searchParams)



  return (
    <>
      <PrivateLayout>
        <div className="container p-2 mx-auto sm:p-4 dark:text-gray-100">
          <ContactTable data={results} />
        </div>

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
  const contacts = await serverMethod(
    `/contacts`,
    params
  );



  return contacts

}


export async function generateMetadata({ params }) {
  return {
    title: " Contact Lists",
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