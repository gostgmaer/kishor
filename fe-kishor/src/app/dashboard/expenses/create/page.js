import PrivateLayout from "@/components/global/layout/privateLayout";
import { CreateExpense, ExpenseSummery } from "@/components/page/expenses/elements";
import { serverMethod } from "@/lib/servermethod";
import { useSession } from "next-auth/react";
import { cookies } from "next/headers";

export const fetchCurrentProfile = async () => {

  const cookieStore = cookies()
  const tokendata = "Bearer " + cookieStore.get("headerPayload")?.value + "." + cookieStore.get("signature")?.value;
  const param = {
    method: "get",
    header: {
      Authorization: tokendata,
    },
  }
  const result = await serverMethod(`/authentication/user/current/profile`, param)
  return result
}


export async function generateMetadata({ params }) {
  return {
    title: " Create Expenses",
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

const Page = async () => {




  return (
    <PrivateLayout>

      <div>
        <CreateExpense  />
      </div>


    </PrivateLayout>
  );
};

export default Page;
