import {
  FaFacebook,
  FaGithub,
  FaHome,
  FaInstagram,
  FaLinkedin,
  FaUser,
} from "react-icons/fa";
import { MdApps, MdContacts } from "react-icons/md";

export const projects = [
  {
    id: 1,
    name: "Gabriel",
    description: "LCM",
    url: "GRU",
    technology: "Female",
    language: [],
    avater: "http://dummyimage.com/250x.png/ff4444/ffffff",
    image: "http://dummyimage.com/250x.png/5fa2dd/ffffff",
    desc_long: "TMN",
    images: "SACC",
    status: "SA",
  },

  {
    id: 20,
    name: "Nathalia",
    description: "MPV",
    url: "DJO",
    technology: "Genderqueer",
    language: [],
    avater: "http://dummyimage.com/250x.png/5fa2dd/ffffff",
    image: "http://dummyimage.com/250x.png/dddddd/000000",
    desc_long: "KWK",
    images: "KMPV",
    status: "NA",
  },
];
export const socialmedia = [
  {
    id: 1,
    icon: <FaGithub className="w-5 h-5" />,
    name: "Github",
    url: "https://github.com/gostgmaer",
    text: "Github",
  },
  {
    id: 2,
    icon: <FaLinkedin className="w-5 h-5" />,
    name: "Linkedin",
    url: "https://www.linkedin.com/in/kishor-sarkar/",
    text: "Linkedin",
  },
  {
    id: 3,
    icon: <FaFacebook className="w-5 h-5" />,
    name: "Facebook",
    url: "https://www.facebook.com/GOST.RKS",
    text: "Facebook",
  },
  {
    id: 4,
    icon: <FaInstagram className="w-5 h-5" />,
    name: "Instagram",
    url: "https://www.instagram.com/kishor.sarkar.in/",
    text: "Instagram",
  },
];
export const urls = [
  {
    id: 10,
    text: "Home",
    url: "/",
    icon: <FaHome className="w-5 h-5" />,
    navigation: "home",
  },
  {
    id: 4,
    text: "about",
    url: "/about",
    icon: <FaUser className="w-5 h-5" />,
    navigation: "about",
  },

  {
    id: 2,
    text: "portfolio",
    url: "/portfolio",
    icon: <MdApps className="w-5 h-5" />,
    navigation: "portfolio",
  },
  {
    id: 1,
    text: "contact",
    url: "/contact",
    icon: <MdContacts className="w-5 h-5" />,
    navigation: "contact",
  },
];
export const resumeContent = {
  experiance: {
    title: "Work Experiances",
    data: [
      {
        id: 1,
        position: "Froentend Developer",
        company: "Inadev India",
        start_time: "2022-06-16 05:08:21",
        end_time: "2022-08-07 10:27:46",
        details: [
          {
            id: 1,
            value: "Killian",
          },
          {
            id: 2,
            value: "Gavrielle",
          },
          {
            id: 3,
            value: "Ninnetta",
          },
          {
            id: 4,
            value: "Kelley",
          },
          {
            id: 5,
            value: "Doralin",
          },
        ],
      },
      {
        id: 2,
        position: "Marketing",
        company: "Oodoo",
        start_time: "2023-01-16 10:59:55",
        end_time: "2022-12-31 08:28:44",
        details: [
          {
            id: 1,
            value: "Killian",
          },
          {
            id: 2,
            value: "Gavrielle",
          },
          {
            id: 3,
            value: "Ninnetta",
          },
          {
            id: 4,
            value: "Kelley",
          },
          {
            id: 5,
            value: "Doralin",
          },
        ],
      },
      {
        id: 3,
        position: "Human Resources",
        company: "Voolia",
        start_time: "2023-05-17 20:24:12",
        end_time: "2022-07-30 17:34:36",
        details: [
          {
            id: 1,
            value: "Killian",
          },
          {
            id: 2,
            value: "Gavrielle",
          },
          {
            id: 3,
            value: "Ninnetta",
          },
          {
            id: 4,
            value: "Kelley",
          },
          {
            id: 5,
            value: "Doralin",
          },
        ],
      },
    ],
  },
  technical_skills: {
    title: "Technical Skills",
    skills: [
      {
        id: 1,
        skill: "Training",
        scale: 3.8,
      },
      {
        id: 2,
        skill: "Training",
        scale: 4.1,
      },
      {
        id: 3,
        skill: "Marketing",
        scale: 1.9,
      },
      {
        id: 4,
        skill: "Legal",
        scale: 2.2,
      },
      {
        id: 5,
        skill: "Legal",
        scale: 3.0,
      },
      {
        id: 6,
        skill: "Marketing",
        scale: 2.4,
      },
      {
        id: 7,
        skill: "Human Resources",
        scale: 2.2,
      },
      {
        id: 8,
        skill: "Legal",
        scale: 3.9,
      },
      {
        id: 9,
        skill: "Legal",
        scale: 2.7,
      },
      {
        id: 10,
        skill: "Training",
        scale: 2.4,
      },
    ],
  },
  profession_skills: {
    title: "Professional Skills",
    skills: [
      {
        id: 1,
        skill: "Business Development",
        scale: 4.3,
      },
      {
        id: 2,
        skill: "Human Resources",
        scale: 2.2,
      },
      {
        id: 3,
        skill: "Research and Development",
        scale: 1.6,
      },
      {
        id: 4,
        skill: "Human Resources",
        scale: 2.7,
      },
      {
        id: 5,
        skill: "Training",
        scale: 1.6,
      },
    ],
  },
  education: {
    title: "Education",
    data: [
      {
        id: 1,
        grade: 7.52,
        college_name: "CGEC",
        department: "Computer Science",
        degree: "B.E",
        start_date: "2017-09-01 15:55:41",
        end_date: "2020-05-17 14:37:52",
        location: "Coochbehar,India",
        coursework: [
          "Web application Development",
          "Client-side scripting",
          "Computer Science",
          "Object-Oriented Programming"
        ],
      },
      {
        id: 5,
        grade: 5.81,
        college_name: "IIT, Bangalore",
        department: "Computer Science",
        degree: "B.E",
        start_date: "2022-12-27 15:55:41",
        end_date: "2022-10-17 14:37:52",
        location: "17 Burrows Point",
        coursework: [
          "Web Development",
          "Client-side scripting",
          "Web architecture",
          "Object-Oriented Programming",
          "Mobile application development",
        ],
      },
    ],
  },
  projects: [
    {
      "deployedUrl": "https://next-personal-seven.vercel.app/",
      "description": "The Personal Portfolio Website built with Next.js is a dynamic and versatile web application designed to showcase your skills, achievements, and creative work to the world. This project leverages the power of Next.js, a popular React framework, to create a seamless and highly responsive web experience that not only impresses visitors but also highlights your unique talents and expertise.",
      "overview": "This project is for for me as a UI developer",
      "projectTitle": "Personal Portfolio",
      "repositoryUrl": "https://github.com/gostgmaer/next-personal",
      "title": ""
    },
    {
      "deployedUrl": "https://next-resume-builder-olive.vercel.app/",
      "description": "This project is not yet done still working on this project",
      "overview": "A resume Builder nextjs Application",
      "projectTitle": "Resume Builder",
      "repositoryUrl": "https://github.com/gostgmaer/next-resume-builder",
      "title": ""
    }
  ],
  profile: {
    name: "Kishor Sarkar",
    contact: [
      {
        id: 1,
        text: "Glover-Gusikowski",
        urls: "Support",
      },
      {
        id: 2,
        text: "Romaguera Inc",
        urls: "Accounting",
      },
    ],
    language: [
      {
        id: 1,
        language: "Croatian",
        profeciancy: 23,
      },
      {
        id: 2,
        language: "Gujarati",
        profeciancy: 51,
      },
      {
        id: 3,
        language: "Assamese",
        profeciancy: 14,
      },
    ],
    socialMedia: [
      {
        id: 1,
        social: "spiegel.de",
        name: "Quimba",
        url: "https://blinklist.com/volutpat/erat/quisque/erat/eros/viverra.js?in=ultrices&faucibus=vel&orci=augue&luctus=vestibulum&et=ante&ultrices=ipsum&posuere=primis&cubilia=in&curae=faucibus&donec=orci&pharetra=luctus&magna=et&vestibulum=ultrices&aliquet=posuere&ultrices=cubilia&erat=curae&tortor=donec&sollicitudin=pharetra&mi=magna&sit=vestibulum&amet=aliquet&lobortis=ultrices&sapien=erat&sapien=tortor&non=sollicitudin&mi=mi&integer=sit&ac=amet&neque=lobortis&duis=sapien&bibendum=sapien&morbi=non&non=mi&quam=integer&nec=ac",
        className: "Platov International Airport",
      },
      {
        id: 2,
        social: "google.nl",
        name: "Edgeblab",
        url: "http://umich.edu/nunc/commodo/placerat/praesent/blandit/nam.js?congue=libero&etiam=rutrum&justo=ac&etiam=lobortis&pretium=vel",
        className: "Swan River Airport",
      },
      {
        id: 3,
        social: "aol.com",
        name: "Devcast",
        url: "https://tripadvisor.com/nonummy.aspx?morbi=vel&sem=nulla&mauris=eget&laoreet=eros&ut=elementum&rhoncus=pellentesque&aliquet=quisque&pulvinar=porta&sed=volutpat&nisl=erat&nunc=quisque&rhoncus=erat&dui=eros&vel=viverra&sem=eget&sed=congue&sagittis=eget&nam=semper&congue=rutrum&risus=nulla&semper=nunc&porta=purus&volutpat=phasellus&quam=in&pede=felis&lobortis=donec&ligula=semper&sit=sapien&amet=a&eleifend=libero&pede=nam&libero=dui&quis=proin&orci=leo&nullam=odio&molestie=porttitor&nibh=id&in=consequat&lectus=in&pellentesque=consequat&at=ut&nulla=nulla&suspendisse=sed&potenti=accumsan&cras=felis&in=ut&purus=at&eu=dolor&magna=quis&vulputate=odio&luctus=consequat&cum=varius&sociis=integer&natoque=ac&penatibus=leo&et=pellentesque&magnis=ultrices&dis=mattis&parturient=odio&montes=donec&nascetur=vitae&ridiculus=nisi&mus=nam&vivamus=ultrices&vestibulum=libero&sagittis=non&sapien=mattis&cum=pulvinar&sociis=nulla&natoque=pede",
        className: "Northeast Philadelphia Airport",
      },
      {
        id: 4,
        social: "bbb.org",
        name: "Zoomzone",
        url: "https://dailymotion.com/lacus.xml?donec=sociis&posuere=natoque&metus=penatibus&vitae=et&ipsum=magnis&aliquam=dis&non=parturient&mauris=montes&morbi=nascetur&non=ridiculus&lectus=mus&aliquam=vivamus&sit=vestibulum&amet=sagittis&diam=sapien&in=cum&magna=sociis&bibendum=natoque&imperdiet=penatibus&nullam=et&orci=magnis&pede=dis&venenatis=parturient&non=montes&sodales=nascetur&sed=ridiculus&tincidunt=mus&eu=etiam&felis=vel&fusce=augue&posuere=vestibulum&felis=rutrum&sed=rutrum&lacus=neque&morbi=aenean&sem=auctor&mauris=gravida&laoreet=sem&ut=praesent&rhoncus=id&aliquet=massa&pulvinar=id&sed=nisl&nisl=venenatis&nunc=lacinia&rhoncus=aenean&dui=sit&vel=amet&sem=justo&sed=morbi&sagittis=ut&nam=odio&congue=cras&risus=mi&semper=pede&porta=malesuada&volutpat=in&quam=imperdiet&pede=et&lobortis=commodo&ligula=vulputate&sit=justo&amet=in&eleifend=blandit&pede=ultrices&libero=enim&quis=lorem&orci=ipsum&nullam=dolor&molestie=sit&nibh=amet&in=consectetuer&lectus=adipiscing&pellentesque=elit&at=proin&nulla=interdum&suspendisse=mauris&potenti=non&cras=ligula&in=pellentesque&purus=ultrices&eu=phasellus&magna=id&vulputate=sapien&luctus=in&cum=sapien&sociis=iaculis&natoque=congue&penatibus=vivamus&et=metus&magnis=arcu",
        className: "Truscott-Mungalalu Airport",
      },
    ],
    address: {},
    position: "Front-end Developer",
    summery:
      "Strong in Design and development with problem-solving skills, Proficient in React.js, JavaScript, node.js, Html CSS, and SQL. very excited to implement and work with new projects, and always love to learn new technologies and tools. Looking to start my career as an entry-level software engineer or developer in a great working environment",
  },
  others_activity: [
    {
      id: 1,
      activity: "Syracuse",
      color: "#21e2bf",
    },
    {
      id: 2,
      activity: "Puerto Inírida",
      color: "#cf05af",
    },
    {
      id: 3,
      activity: "Kindu",
      color: "#52e137",
    },
    {
      id: 4,
      activity: "Enid",
      color: "#33da1c",
    },
    {
      id: 5,
      activity: "Belle Chasse",
      color: "#4b5e0f",
    },
  ],
  referance: {
    title: "Referance",
    data: [
      {
        id: 1,
        grade: 5.81,
        name: "New User",
        deg: "Project manager",
        email: "B.E",
      },
      {
        id: 2,
        grade: 5.81,
        name: "New User",
        deg: "Project manager",
        email: "B.E",
      },
    ],
  },
  name: "Thomas Davis",
  label: "Web Developer",
  image: "https://avatars.githubusercontent.com/u/43110343?v=4",
  summary:
    "I'm a full stack web developer who can build apps from the ground up. I've worked mostly at startups so I am used to wearing many hats. I am a very product focussed developer who priotizes user feedback first and foremost. I'm generally very flexible when investigating new roles. ",
  website: "https://lordajax.com",
  email: "thomasalwyndavis@gmail.com",
  location: {
    city: "Melbourne",
    countryCode: "AU",
  },
  profiles: [
    {
      username: "ajaxdavis",
      url: "https://twitter.com/ajaxdavis",
      network: "twitter",
    },
    {
      url: "https://github.com/thomasdavis",
      username: "thomasdavis",
      network: "github",
    },
  ],

  // "education": [
  //   {
  //     "endDate": "2009-12-12",
  //     "startDate": "2008-02-12",
  //     "area": "Software Engineering (incomplete)",
  //     "studyType": "Bachelors",
  //     "institution": "The University of Queensland"
  //   }
  // ],
  // "references": [
  //   {
  //     "reference": "Thomas was hired as a lead developer and, upon the leaving of our co-founder took over as CTO of Earbits. Thomas is, hands down, one of those A Players you hear of companies dying to hire. He is incredibly smart, not just at code but about everything from classical music to Chinese language and culture. Thomas is great to work with and, as a well established contributor to open source projects and several successful ventures, commands the respect of engineers at all levels. I would suggest doing anything you can to have him on your team.",
  //     "name": "Joey Flores, Co-founder and CEO of Earbits, Inc."
  //   },
  //   {
  //     "reference": "I've had the great pleasure of working with Thomas for the past three years at Earbits, and on a few side projects. Two years ago our CTO left on a moment's notice, Thomas saved our company by quickly stepping up to fill this role. He has been with our company through thick and thin and made serious personal sacrifices in order to help the company during tough times. He is a phenomenal hacker and a true team player. Highly recommended!",
  //     "name": "Yotam Rosenbaum, SVP of Operations, Earbits, Inc."
  //   },
  //   {
  //     "reference": "Thomas is an extremely talented engineer with a very broad range of skills and experience. From being a thought leader in the front-end community via backbonetutorials.com and cdnjs.com, to designing and implementing the API for cdnjs.com, working with Thomas has been fantastic learning experience. Thomas is truly a full stack develop, and his work output is incredible. If there is any opportunity to work with Thomas, I take it. He is the definition of an A player.",
  //     "name": "Ryan Kirkman, Senior Software Engineer at Nerdwallet"
  //   },
  //   {
  //     "reference": "On Thomas Davis... Hire this guy. Do not be fooled. Incredibly capable and fast. Plays well with others. Unbelievable at front-end work end programming but that is just the start. Visionary. Hire him before I do.",
  //     "name": "Greg Davis"
  //   }
  // ],
  skills: [
    {
      keywords: [
        "HTML / JSX",
        "SCSS / CSS / Styled Components",
        "Javascript / Typescript",
        "React.js / Next.js",
        "Redux ",
      ],
      level: "Entry Level",
      name: "Frontend",
    },
    {
      keywords: ["Node.js", "Postgres", "MongoDb", "Serverless"],
      level: "Entry Level",
      name: "Backend",
    },
    {
      keywords: ["AWS", "Heroku", "Caching"],
      level: "Entry Level",
      name: "Devops",
    },
  ],
  awards: [
    {
      title: "Spotlight of the Organization",
      awarder: "2022",
    },
  ],
  work: [
    {
      summary:
        "Worked as a Product Configurator and UI developer write cross platform web applicaion, awarded two time as spotlight and kudos ",
      website: "https://www.inadev.com/",
      name: "Inadev India",
      location: "Kolkata",
      position: "Front End Developer",
      startDate: "2021-08-02",
      highlights: ["Css", "HTML5", "SCSS", "Ceebit", "Javascript", "Typescript", "Angular"],
    }
  ],
  interests: [
    {
      name: "Gardening",
    },
    {
      name: "Travlling ",
    },
    {
      name: "Reading / Writing",
    },
    {
      name: "Open Source",
    },
  ],
  languages: [
    {
      language: "English",
      fluency: "Intermediate",
      read: 1,
      write: 1,
      speak: 1,
    },
    {
      language: "Hindi",
      fluency: "begineer",
      read: 0,
      write: 0,
      speak: 1,
    },
    {
      language: "Bengali",
      fluency: "Native speaker",
      read: 1,
      write: 1,
      speak: 1,
    },
  ],
};

export const userInfo = {
  name: {
    first: "Kishor",
    last: "Sarkar",
  },
  contact: {
    street: "123 Main Street",
    city: "Kolkata",
    country: "India",
    email: "kishor.sarkar.in@gmail.com",
    phone: "863-731-7273",
    countryCode: "+91",
    coordionate: {
      "lon": 87.5275,
      "lat": 23.9109
    }
  },
  image: "https://avatars.githubusercontent.com/u/43110343?v=4",
  about:
    "Cuber and Self-Taught Front-end Software Developer, I enjoy building responsive web apps & designs using HTML5, CSS3, JavaScript, Next.js, React.js, Firebase, Restful APIs.., I have been working on the web for around 3 years building freelance/learning projects.",
};

export const techCate = [
  {
    "id": 1,
    "name": "Frontend Development",
    "considerations": [
      { "id": 1, "name": "UI Design" },
      { "id": 2, "name": "UX Design" },
      { "id": 3, "name": "HTML/CSS/JavaScript" }
    ]
  },
  {
    "id": 2,
    "name": "Backend Development",
    "considerations": [
      { "id": 4, "name": "Server-side Programming" },
      { "id": 5, "name": "Database Design and Management" },
      { "id": 6, "name": "API Development" }
    ]
  },
  {
    "id": 3,
    "name": "Infrastructure",
    "considerations": [
      { "id": 7, "name": "Hosting" },
      { "id": 8, "name": "Deployment" },
      { "id": 9, "name": "Scalability" }
    ]
  },
  {
    "id": 4,
    "name": "Security",
    "considerations": [
      { "id": 10, "name": "Authentication and Authorization" },
      { "id": 11, "name": "Data Encryption" },
      { "id": 12, "name": "Input Validation" }
    ]
  },
  {
    "id": 5,
    "name": "Performance",
    "considerations": [
      { "id": 13, "name": "Optimization" },
      { "id": 14, "name": "Caching" },
      { "id": 15, "name": "Monitoring" }
    ]
  },
  {
    "id": 6,
    "name": "Testing",
    "considerations": [
      { "id": 16, "name": "Unit Testing" },
      { "id": 17, "name": "Integration Testing" },
      { "id": 18, "name": "End-to-End Testing" }
    ]
  },
  {
    "id": 7,
    "name": "Accessibility",
    "considerations": [
      { "id": 19, "name": "Compliance" },
      { "id": 20, "name": "Keyboard Navigation" },
      { "id": 21, "name": "Screen Reader Compatibility" }
    ]
  },
  {
    "id": 8,
    "name": "Documentation",
    "considerations": [
      { "id": 22, "name": "Code Documentation" },
      { "id": 23, "name": "User Documentation" }
    ]
  },
  {
    "id": 9,
    "name": "Version Control",
    "considerations": [
      { "id": 24, "name": "Git" },
      { "id": 25, "name": "Branching and Merging" }
    ]
  },
  {
    "id": 10,
    "name": "Project Management",
    "considerations": [
      { "id": 26, "name": "Agile/Scrum" },
      { "id": 27, "name": "Task Management" }
    ]
  },
  {
    "id": 11,
    "name": "Legal and Compliance",
    "considerations": [
      { "id": 28, "name": "Privacy Policies" },
      { "id": 29, "name": "Terms of Service" }
    ]
  },
  {
    "id": 12,
    "name": "Localization and Internationalization",
    "considerations": [
      { "id": 30, "name": "Localization" },
      { "id": 31, "name": "Internationalization" }
    ]
  },
  {
    "id": 13,
    "name": "Analytics and Monitoring",
    "considerations": [
      { "id": 32, "name": "Usage Analytics" },
      { "id": 33, "name": "Error Monitoring" }
    ]
  },
  {
    "id": 14,
    "name": "Feedback and Iteration",
    "considerations": [
      { "id": 34, "name": "User Feedback" },
      { "id": 35, "name": "Iterative Development" }
    ]
  }
]

export const expenseData = {
  savings: [
    {
      name: "January Savings 1",
      category: "Emergency Fund",
      amount: 1000,
      date: "2024-01-05",
      description: "Transfer to emergency fund"
    },
    {
      name: "January Savings 2",
      category: "Retirement",
      amount: 500,
      date: "2024-01-15",
      description: "Contribution to retirement savings"
    },
    {
      name: "January Savings 3",
      category: "Travel Fund",
      amount: 200,
      date: "2024-01-25",
      description: "Savings for upcoming travel"
    }
  ],
  incomes: [
    {
      name: "January Income 1",
      category: "Salary",
      amount: 3000,
      date: "2024-01-05",
      description: "First payment of the month"
    },
    {
      name: "January Income 2",
      category: "Salary",
      amount: 2000,
      date: "2024-01-15",
      description: "Second payment of the month"
    },
    {
      name: "January Income 3",
      category: "Bonus",
      amount: 1500,
      date: "2024-01-25",
      description: "Year-end bonus payment"
    },
    {
      name: "January Income 4",
      category: "Freelance",
      amount: 1000,
      date: "2024-01-10",
      description: "Payment for freelance project"
    },
    {
      name: "January Income 5",
      category: "Investment",
      amount: 500,
      date: "2024-01-20",
      description: "Dividend income"
    }
  ], expenses: [
    {
      name: "January Expense 1",
      category: "Rent",
      amount: 1500,
      date: "2024-01-05",
      description: "Monthly rent payment"
    },
    {
      name: "January Expense 2",
      category: "Groceries",
      amount: 300,
      date: "2024-01-10",
      description: "Grocery shopping for the month"
    },
    {
      name: "January Expense 3",
      category: "Utilities",
      amount: 200,
      date: "2024-01-15",
      description: "Utility bills payment"
    },
    {
      name: "January Expense 4",
      category: "Transportation",
      amount: 100,
      date: "2024-01-20",
      description: "Public transportation cost"
    },
    {
      name: "January Expense 5",
      category: "Entertainment",
      amount: 50,
      date: "2024-01-25",
      description: "Movie night with friends"
    },
    {
      name: "January Expense 6",
      category: "Healthcare",
      amount: 150,
      date: "2024-01-08",
      description: "Doctor's visit co-pay"
    },
    {
      name: "January Expense 7",
      category: "Dining Out",
      amount: 80,
      date: "2024-01-12",
      description: "Dinner at a restaurant"
    }
  ],name:"March Expense",monyh:"March"

}