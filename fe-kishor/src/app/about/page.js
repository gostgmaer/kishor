import { userInfo } from "@/assets/data/mock";
import PageLayout from "@/components/global/layout/pageLayout";

import Image from "next/image";
import React from "react";


export async function generateMetadata({ params }) {
  return {
    title: "Kishor Sarkar About ",
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
    <PageLayout >
      <div className=" rounded-[20px] m-5 sm:m-auto  shadow-md  bg-gray-100 flex items-center justify-center">
        <div className="min-h-max p-4 sm:p-8 w-full sm:flex">
          <div className=" sm:w-2/3 pr-8">
            <h1 className="text-2xl font-semibold mb-4">About Me</h1>
            <p className="mb-4">
              I am a passionate and dedicated web developer with years of
              experience in creating modern and responsive websites. My goal is
              to provide the best web solutions to clients, meeting their unique
              needs and exceeding their expectations.
            </p>
            <p className="mb-4">
              I specialize in front-end development, using cutting-edge
              technologies like React, Next.js, and Tailwind CSS to build
              user-friendly and visually appealing websites. Whether you re
              looking for a personal portfolio or an e-commerce platform, I can
              help bring your ideas to life.
            </p>
            <p>
              Let s collaborate on your next project and create something
              amazing together. Contact me using the form on the right, and I ll
              get back to you as soon as possible.
            </p>
            <p>
              {" "}
              Cuber and Self-Taught Front-end Software Developer, I enjoy
              building responsive web apps & designs using HTML5, CSS3,
              JavaScript, Next.js, React.js, Firebase, Restful APIs.., I have
              been working on the web for around 3 years building
              freelance/learning projects.
            </p>
          </div>
          <div className="sm:w-1/3">
            <div className="bg-gray-100 text-white px-4 py-2 h-96 rounded">
              <Image
                src={userInfo.image} // Replace with the actual path to your image
                alt={userInfo.name.first}
                height={384}
                width={350}
                className="rounded-full  object-cover"
              />
            </div>
          </div>
        </div>
      </div>
    </PageLayout>
  );
};

export default Index;
