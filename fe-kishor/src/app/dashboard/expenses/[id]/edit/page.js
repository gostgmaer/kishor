import PrivateLayout from "@/components/global/layout/privateLayout"
import { ExpenseSummery } from "@/components/page/expenses/elements";
import { serverMethod } from "@/lib/servermethod"

export async function generateMetadata({ params }) {
  return {
    title: " Update Expenses",
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

  const expenses = await getRecord(props.params.id)


  return (
    <PrivateLayout>

      <ExpenseSummery />

    </PrivateLayout>
  )
}

export default Page



export const getRecord = async (id) => {

  const params = {
    method: "get",
    header: {},
    query: {},
  };
  const contacts = await serverMethod(
    `/expenses/${id}`,
    params
  );
  return contacts

}