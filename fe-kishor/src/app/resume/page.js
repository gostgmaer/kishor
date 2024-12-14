import React from "react";
import { resumeContent } from "@/assets/data/mock";
import {
  FaAward,
  FaBusinessTime,
  FaUniversity,
} from "react-icons/fa";
import {
  MdAddChart,
  MdApps,
  MdContacts,
  MdLanguage,
  MdLocationCity,
  MdMail,
  MdPeople,
  MdPerson,
  MdPhone,
  MdWeb,
} from "react-icons/md";
import Head from "next/head";
// import DownloadResume from "@/components/Resume/Others/DownloadResume";
import PageLayout from "@/components/global/layout/pageLayout";
import Image from "next/image";
import Link from "next/link";
import moment from "moment";
import { calculateTimeGap } from "@/helper/function";
import DownloadResume from "@/components/Resume/Others/DownloadResume";
import ResumeIndex from "@/components/page/my-resume";

export async function generateMetadata({ params }) {
  return {
    title: "Kishor Sarkar Resume",
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
    <div className=" container relative mx-auto scroll-my-12 overflow-auto p-4 print:py-12 md:p-16 ">
      <DownloadResume />
      <ResumeIndex/>
    </div>
  );
};

export default Index;

const Projects = () => {
  return (
    <div className=" my-2">
      <h3 className="text-2xl my-1 font-semibold flex gap-2 items-center print:text-xl">
        {" "}
        <MdApps className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
        PROJECTS
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {resumeContent.projects.map((project, index) => (
          <div key={index} className="p-4 border rounded-lg shadow-md">
            <h2 className="text-xl font-semibold">{project.projectTitle}</h2>
            <p className="text-gray-600">
              {project.overview.substring(0, 35)}...
            </p>
            <div className="mt-2 print:hidden">
              <a
                href={project.deployedUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-500 hover:underline mr-4"
              >
                Demo
              </a>
              <a
                href={project.repositoryUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-500 hover:underline"
              >
                Repository
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// const DownloadResume = () => {


//   function downloadFile() {
//     var link = document.createElement("a");
//     link.href = "./assets/file/kishor.pdf";
//     link.download = "Kishor.pdf";
//     document.body.appendChild(link);
//     link.click();
//     document.body.removeChild(link);
//   }

//   const handlePrint = () => {
//     window.print();
//   };

//   return (
//     <div className="action-btn print:hidden">
//       <div className="mt-4 flex w-full items-center justify-end">
//         <button
//           onClick={downloadFile}
//           className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mr-2"
//         >
//           Download
//         </button>
//         <button
//           onClick={handlePrint}
//           className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
//         >
//           Print
//         </button>
//       </div>
//     </div>
//   );
// };

const LeftContent = () => {
  return (
    <div className="topcontent print:h-screen  flex flex-col justify-between items-center w-full bg-blue-100 text-dark">
      <div className="name-image">
        <div className="name text-center print:px-5 py-10 text-white  bg-[#442fb9]">
          <h1 className="text-4xl print:text-3xl font-bold">Kishor Sarkar</h1>
          <h3 className="text-xl print:text-lg space-x-1">
            Front-End Developer
          </h3>
        </div>
        <div className="image pt-5 p-3  rounded-b-full bg-[#442fb9]">
          <div className="profile-img bg-white  p-3 rounded-full ">
            <Image
              className="w-auto rounded-full"
              // src={"/assets/images/kishor.png"}
              src={resumeContent.image}
              width={320}
              height={320}
              alt="Kishor Sarkar"
            />
          </div>
        </div>
      </div>
      <div className="bottomSection w-full ">
        {/* Contact Information */}
        <div className="contact text-lg flex flex-col gap-2 py-5 print:py-4 text-black">
          <h2 className="font-bold text-2xl flex align-middle justify-center gap-2 items-center ">
            <MdContacts className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
            Contact Me
          </h2>
          <div className="contact-info px-10 text-lg print:px-4 print:text-sm">
            <Link
              href={"mailto:kishor.sarkar.in@gmail.com"}
              className=" flex align-middle justify-start gap-2 items-center "
            >
              <MdMail /> kishor.sarkar.in@gmail.com
            </Link>
            <Link
              href={"tel:+918637317372"}
              className=" flex align-middle justify-start gap-2 items-center"
            >
              <MdPhone /> +918637317372
            </Link>
            <Link
              href={"https://next-personal-seven.vercel.app/"}
              target="_blank"
              className="flex items-center gap-2 justify-start transform transition-transform hover:scale-105"
            >
              <MdWeb /> Portfolio Page
            </Link>
            <div className="contact-address  flex align-middle justify-start gap-2 items-center">
              <MdLocationCity /> <p className="">West bengal, India</p>
            </div>
          </div>
        </div>
        <div className="bottom-curve  text-white  w-full print:px-4 px-5">
          {/* EDUCATION */}
          <div className="education flex flex-col justify-center items-start pt-20 gap-1 rounded-t-full  bg-black p-16 print:pt-16 print:p-5 ">
            <div className="title w-full">
              <h3 className="text-2xl print:text-lg flex gap-3 items-center justify-start uppercase font-semibold">
                <FaUniversity className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
                {resumeContent.education.title}
              </h3>
            </div>
            <div className="experiancecontent flex flex-col gap-4">
              {resumeContent.education.data.map((data) => (
                <div className="education" key={data.id}>
                  <h4 className="college font-semibold text-lg">
                    {data.college_name}
                  </h4>
                  <p className="degree font-medium text-sm ">
                    {data.degree} in {data.department}
                  </p>

                  <p className="timeline text-sm">
                    <span>{moment(data.start_date).format("YYYY")}</span> -
                    <span> {moment(data.end_date).format("YYYY")}</span>
                  </p>
                </div>
              ))}
            </div>
          </div>
          {/* referance */}
          <div className="Referance print:pt-2 flex flex-col justify-center items-start  pt-0 gap-1  bg-black p-16 print:p-5 ">
            <div className="title w-full">
              <h3 className="text-2xl print:text-lg flex gap-3 items-center justify-start uppercase font-semibold">
                <MdPeople className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
                {resumeContent.referance.title}
              </h3>
            </div>
            <div className="experiancecontent flex flex-col gap-4">
              {resumeContent.referance.data.map((data) => (
                <div className="education" key={data.id}>
                  <h4 className="college font-semibold text-lg">{data.name}</h4>
                  <p className="degree font-medium text-sm ">{data.deg}</p>
                  <p className="timeline text-sm">
                    <span>{data.email}</span>
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const Objectivity = () => {
  return (
    <div className="objectivity w-full pt-10 ">
      <h3 className="text-xl font-bold uppercase flex items-center gap-2 ">
        {" "}
        <MdPerson className=" bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
        About Me
      </h3>
      <p className=" text-justify mt-2 print:text-xs text-sm">
        {resumeContent.profile.summery}
      </p>
    </div>
  );
};

const Experiances = () => {
  return (
    <div className="experiances">
      <div className="title flex gap-2 items-center justify-start">
        <h3 className="text-2xl font-semibold flex gap-2 items-center print:text-xl">
          {" "}
          <FaBusinessTime className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
          WORK EXPERIENCE
        </h3>
      </div>
      <div className="experiancecontent flex flex-col gap-2 print:gap-1">
        {resumeContent.work.map((data, index) => (
          <div key={index} className="workExperiance flex flex-col gap-0">
            <div className="top flex justify-between items-center">
              <h4 className="position font-semibold text-lg print:text-sm">
                {data.position}
              </h4>
              <p className="timeline">
                <span className=" print:text-xs">
                  {moment(data.startDate).format("MMM YYYY")} -{" "}
                  {data.endDate
                    ? moment(data.end_time).format("YYYY")
                    : "Present"}
                </span>
                {data.endDate && (
                  <span className=" font-medium  print:text-sm">
                    {" "}
                    ({calculateTimeGap(
                      data.startDate,
                      data.endDate,
                      "1 years"
                    )}{" "}
                    )
                  </span>
                )}
              </p>
            </div>

            <div className="organization  print:text-sm">
              <h5 className="company italic font-medium">
                {data?.name}, {data?.location}
              </h5>
              <span>{data.website}</span>
            </div>

            <div className="Summery  print:text-sm">
              <h5 className="font-semibold">Summery</h5>
              <p className="text-justify print:text-xs">{data.summary}</p>
              <ul className=" pl-10 flex items-center gap-2 flex-wrap p-2 print:gap-1 print:p-2 print:pl-5">
                {data?.highlights?.map((item) => (
                  <li key={item} className=" p-1 italic py-0">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const SkillSet = () => {
  return (
    <div className="experiances">
      <div className="title flex gap-2 items-center justify-start">
        <h3 className="text-2xl font-semibold flex gap-2 items-center print:text-xl uppercase">
          <MdAddChart className="bg-slate-800 h-6 w-6 text-white rounded-full p-1 " />{" "}
          Skills
        </h3>
      </div>
      <div className="experiancecontent flex flex-col gap-5 print:gap-3">
        {resumeContent.skills.map((data, index) => (
          <div key={index} className="skill flex flex-col gap-2">
            <div className="name-position flex items-center gap-3">
              <h4 className="name font-semibold text-xl  print:text-xl ">
                {data.name}
              </h4>
              <h5 className="level bg-slate-400 text-white font-normal py-0 px-1 rounded">
                {data.level}
              </h5>
            </div>
            <div className="keywords">
              <ul className="flex flex-wrap gap-2">
                {data.keywords.map((item) => (
                  <li
                    className="bg-blue-500  text-white font-medium print:py-0 py-1 px-1 cursor-pointer rounded transition duration-300 ease-in-out hover:bg-blue-700 hover:text-slate-300"
                    key={item}
                  >
                    {" "}
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const Others = () => {
  return (
    <div>
      <div className="Languages flex flex-col gap-2 mt-2 items-start justify-between">
        <div className="">
          <div className="title ">
            <h3 className="text-2xl flex gap-3 items-center justify-start uppercase font-semibold print:text-lg">
              <MdLanguage className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
              Language
            </h3>
          </div>
          <div className="experiancecontent flex items-center gap-1">
            {resumeContent.languages.map((data, index) => (
              <div className="education" key={index}>
                <p className="degree font-medium text-sm  flex gap-1">
                  <span className="language"> {data.language}</span>{" "}
                  <span className="coma">,</span>
                  <span className="flunt">{data.fluency}</span>
                </p>
              </div>
            ))}
          </div>
        </div>
        <div className="">
          <div className="title ">
            <h3 className="text-2xl flex gap-3 items-center justify-start uppercase print:text-lg font-semibold">
              <MdLanguage className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
              Interests
            </h3>
          </div>
          <div className="experiancecontent flex items-center  gap-1">
            {resumeContent.interests.map((data, index) => (
              <div className="education" key={index}>
                <p className="degree font-medium text-sm  flex gap-1">
                  , <span className="language"> {data.name}</span>
                </p>
              </div>
            ))}
          </div>
        </div>
        <div className="award flex flex-col justify-center items-start  pt-0 gap-1">
          <div className="title ">
            <h3 className="text-2xl flex gap-3 items-center justify-start uppercase font-semibold print:text-lg">
              <FaAward className="bg-slate-800 h-6 w-6 text-white rounded-full p-1" />{" "}
              Awards
            </h3>
          </div>
          <div className="experiancecontent flex flex-col gap-4">
            {resumeContent.awards.map((data) => (
              <div className="awardElement" key={data.title}>
                <span className="text font-semibold">{data.title}</span> -
                <span className="name"> {data.awarder}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
