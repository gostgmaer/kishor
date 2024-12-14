import { SiHey } from "react-icons/si";
import { RiProfileLine, RiContactsBookLine } from "react-icons/ri";
import { socialmedia, userInfo } from "@/assets/data/mock";
import PageLayout from "@/components/global/layout/pageLayout";

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

export default function Home() {
  return (
    <PageLayout>
      <div className="">
        <div className="py-12 px-2 w-full m-auto sm:pt-24">
          <h2 className="flex justify-start items-center gap-2 text-xl font-bold text-slate-600 mb-4 sm:text-2xl">
            <span>Hello there</span>
            <SiHey />
            <span>I am</span>
          </h2>
          <h1 className="text-6xl font-bold text-gray-800 sm:text-7xl">
            {userInfo.name.first} {userInfo.name.last}
          </h1>
          <p className="text-md text-gray-600 leading-7 my-4 sm:text-lg sm:leading-8">
            {userInfo.about}
          </p>
          <div className="my-7 flex justify-start items-center gap-4 flex-wrap">
            <button
              className="bg-gray-500 py-2 px-4 font-bold text-white border-2 border-gray-500 rounded-md ease-in-out duration-150 hover:text-gray-500 hover:bg-transparent hover:border-white"
              title="View Resume"
            >
              <a
                href="/resume"
                className="flex justify-start items-center gap-1"
              >
                <span>View Resume</span>
                <RiProfileLine />
              </a>
            </button>
            <button
              className="bg-white py-2 px-4 font-bold text-gray-500 border-2 border-white rounded-md ease-in-out duration-150 hover:text-gray-500 hover:bg-transparent hover:border-gray-500"
              title="Get in touch"
            >
              <a
                href="/contact"
                className="flex justify-start items-center gap-1"
              >
                <span>Get in touch</span>
                <RiContactsBookLine />
              </a>
            </button>
          </div>
          <div className="flex flex-col justify-start items-start gap-3 mt-20">
            <h4 className="text-xl text-gray-700 font-bold">Find me on :</h4>
            <ul className="flex justify-start items-center flex-wrap gap-4">
              {socialmedia.map((item) => (
                <li title={item.name} key={item.id}>
                  <a
                    href={item.url}
                    target="_blank"
                    className="text-gray-500 text-md ease-in-out duration-150 hover:text-gray-800"
                  >
                    {item.icon}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </PageLayout>
  );
}
