import { resumeData } from "@/helper/data";
import Link from "next/link";
import { MdLocationPin, MdMail, MdPhone } from "react-icons/md";

export const ProjectCard = (props) => {

  return (
    <div className="rounded-lg bg-card text-card-foreground flex flex-col overflow-hidden border border-muted p-3">
      <div className="flex flex-col space-y-1.5">
        <p className="font-semibold tracking-tight text-base">Consultly</p>
        <p className="text-muted-foreground font-mono text-sm">
          A platform to build and grow your online business
        </p>
      </div>
      <ul className="mt-2 flex flex-wrap gap-1 text-pretty font-mono text-md text-muted-foreground ">
        {props.data.techStack.map((item, index) => (
          <li
            key={index}
            className="inline-flex items-center rounded-md border font-semibold font-mono transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 text-nowrap border-transparent bg-gray-500 text-gray-50 hover:bg-gray-800 cursor-pointer px-1 py-0 text-[10px]"
          >
            {item}
          </li>
        ))}
      </ul>

      <div className="text-pretty font-mono text-md text-muted-foreground flex justify-start gap-5 mt-2">
        <p className="hover:underline cursor-pointer">Github</p>{" "}
        {props.data.link && <p className="hover:underline cursor-pointer"><Link href={props.data.link.href} target="_blank">URL</Link></p>}
      </div>
    </div>
  );
};

export const ExperianceCard = (props) => {
  return (
    <div className="rounded-lg bg-card text-card-foreground">
      <div className="flex justify-between space-y-1.5 items-center">
        <p>
          <span className="inline-flex items-center justify-center gap-x-1 font-semibold leading-none">{props.data.company}</span>{" "}
          {props.data.badges.length !=0 && <span className="inline-flex items-center rounded-md border cursor-pointer px-2 py-0.5 font-semibold font-mono transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 text-nowrap border-transparent bg-gray-500 text-gray-50 hover:bg-gray-800 align-middle text-sm">
            {props.data.badges[0]}
          </span>}
        </p>
        <p className="text-md tabular-nums text-gray-500 flex gap-2">
          <span> {props.data.start}</span>
          <span> {props.data.end}</span>
        </p>
      </div>
      <div className="text-pretty font-mono text-muted-foreground mt-2 text-sm">
        <p className="font-mono text-md font-medium leading-none">
          {props.data.title}
        </p>
        <p className="text-pretty font-mono text-muted-foreground mt-2 text-sm">
          {props.data.description}
        </p>
      </div>
    </div>
  );
};

export const EducationCard = (props) => {
  return (
    <div className="rounded-lg bg-card text-card-foreground">
      <div className="flex space-y-1.5 w-full justify-between items-center">
        <p className="font-semibold leading-none">
          Wrocław University of Technology
        </p>
        <p className="text-md tabular-nums text-gray-500">
          <span>2007 - 2010</span>
        </p>
      </div>
      <div className="text-pretty font-mono text-md text-muted-foreground mt-2">
        <p>Bachelor&lsquo;s Degree in Control systems engineering and Robotics</p>
      </div>
    </div>
  );
};

export const Resumeheading = (props) => {
  return (
    <div className="flex gap-4">
      <div className="col-span-3 flex-1">
        <p className="text-2xl font-bold">Kishor Sarkar</p>
        <p className="max-w-md text-pretty font-mono text-md text-muted-foreground">
          Full Stack Engineer focused on building products with extra attention
          to detail
        </p>
        <p className="max-w-md items-center text-pretty font-mono text-sm text-muted-foreground flex gap-1">
          <MdLocationPin />  <span>Kolkata</span>  , <span> India</span>
        </p>
        <p className="max-w-md items-center text-pretty font-mono text-sm text-muted-foreground gap-1 hidden print:flex">
           <Link href='mailto://kishor.sarkar.in@gmail.com'  className=" flex items-center "> <MdMail />  kishor.sarkar.in@gmail.com</Link>  , <Link href={'tel:+918637317273'} className=" flex items-center "> <MdPhone/> +918637317273</Link>
        </p>
        <ul className="flex gap-x-2 pt-1 font-mono text-md text-muted-foreground print:hidden">
          {resumeData.contact.social.map((item, index) => (
            <li className="w-4 h-4" key={index}>
              <Link href={item.url} className="w-5 h-5">{item.icon}</Link>
            </li>
          ))}
        </ul>
      </div>
      <div className="col-span-1 ">
        <span className="relative flex shrink-0 overflow-hidden rounded-xl w-28">
          <img
            src="./assets/images/kishor.png"
            className="aspect-square h-full w-full"
          />
        </span>
      </div>
    </div>
  );
};
