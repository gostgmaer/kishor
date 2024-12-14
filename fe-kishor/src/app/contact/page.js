import { socialmedia, userInfo } from "@/assets/data/mock";
import { ContatForm } from "@/components/forms/contact";
import PageLayout from "@/components/global/layout/pageLayout";

export async function generateMetadata({ params }) {
  return {
    title: "Kishor Sarkar Contact",
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

const Index = () => {
  return (
    <PageLayout>
      <div className="  rounded-[20px]  shadow-md m-auto bg-gray-100 flex items-center justify-center my-5">
        <div className="min-h-max sm:p-8 p-4 w-full sm:flex">
          <div className="sm:w-2/3 sm:pr-8 ">
            <h1 className="text-2xl font-semibold mb-4">Contact Us</h1>
            <ContatForm />
          </div>
          <div className="sm:w-1/3 mt-5 sm:mt-0">
            <div className="bg-blue-500 text-white px-4 py-2 rounded">
              <h2 className="text-lg font-semibold mb-2">
                Contact Information
              </h2>
              <p className="mb-2">{userInfo.contact.street}</p>
              <p className="mb-2">
                {userInfo.contact.city}, {userInfo.contact.country}
              </p>
              <p className="mb-2">
                {" "}
                Email:{" "}
                <a href={`mailto:${userInfo.contact.email}`}>
                  {userInfo.contact.email}
                </a>
              </p>
              <p className="mb-2">
                Phone:{" "}
                <a
                  href={`tel:${
                    userInfo.contact.countryCode
                  }${userInfo.contact.phone.replace(/-/g, "")}`}
                >
                  {userInfo.contact.countryCode}-{userInfo.contact.phone}
                </a>
              </p>
              <div className="socialMedia">
                <h3 className=" font-medium mb-1 mt-2 text-lg">Social Media</h3>
                <nav className="flex gap-1">
                  {socialmedia.map((social) => (
                   <span key={social.id}>   {social.icon}</span>
                  ))}
                </nav>
              </div>
              {/* <div className="Coordinate">
              <h3 className=" font-medium mb-1 mt-2 text-lg">Coordinate</h3>
             <p><span>{userInfo}</span></p>
            </div> */}
            </div>
          </div>
        </div>
      </div>
    </PageLayout>
  );
};

export default Index;

