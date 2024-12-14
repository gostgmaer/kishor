import PrivateLayout from "@/components/global/layout/privateLayout";
import { serverMethod } from "@/lib/servermethod";
import moment from "moment";


const Page = async (props) => {

  const results = await getRecord(props.params.id)
  const contact = results.result


  return (
   <> <PrivateLayout>
      <div className="bg-white shadow-md p-4 rounded-lg w-full">
        <h2 className=" text-2xl font-semibold text-blue-600">User Data</h2>
        {!contact ? (
          <div className=" mx-auto my-20 text-center">
            {" "}
            No information found for given id
          </div>
        ) : (
          <ul className="mt-4 space-y-2"> 
            <li>
              <strong>ID:</strong> {contact._id}
            </li>
            <li>
              <strong>First Name:</strong> {contact.firstName}
            </li>
            <li>
              <strong>Last Name:</strong> {contact.lastName}
            </li>
            <li>
              <strong>Email:</strong> {contact.email}
            </li>
            <li>
              <strong>Contact Number:</strong> {contact.country}
              {contact.contactNumber}
            </li>

            <li>
              <strong>Company:</strong> {contact.company}
            </li>
            <li>
              <strong>Subscribe:</strong> {contact.subscribe ? "Yes" : "No"}
            </li>
            <li>
              <strong>Message:</strong>  <div dangerouslySetInnerHTML={{ __html: contact.message }} className=" overflow-hidden" />
            </li>
            <li>
              <strong>Created At:</strong> {moment(contact.createdAt).fromNow()}
            </li>
          </ul>
        )}
      </div>
    
      <div></div>
    </PrivateLayout>
    </>
  );
};

export default Page;


export const getRecord = async (id) => {

  const params = {
    method: "get",
    header: {},
    query: { },
  };
  const contacts = await serverMethod(
    `/contacts/${id}`,
    params
  );
  return contacts

}


export async function generateMetadata({ params }) {
  return {
    title: " Contact Details",
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