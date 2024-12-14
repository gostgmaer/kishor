import PrivateLayout from "@/components/global/layout/privateLayout"
import ProjectForm from "@/components/page/dashboard/projects/form"

const initialValue = {
  title: '',
  description: '',
  startDate: '',
  endDate: '',
  technologiesUsed: [
    {
      category: '',
      name: '',
      description: '',
      proficiency: '',
      version: '',
      documentationLink: '',
    },
  ],
  teamMembers: [],
  status: '',
  current_status: '',
  tasks: [
    {
      title: '',
      description: '',
      status: 'Not Started',
    },
  ],
  client: {
    name: '',
    contactPerson: '',
    contactEmail: '',
  },
  budget: {
    currency: '',
    amount: 0,
  },
  duration: {
    value: 0,
    unit: 'days',
  },
  milestones: [
    {
      title: '',
      description: '',
      dueDate: '',
    },
  ],
  attachments: [],
  notes: '',
  risks: [
    {
      description: '',
      probability: 0,
      impact: '',
      mitigation: '',
    },
  ],
  feedback: [
    {
      date: '',
      from: '',
      message: '',
    },
  ],
  projectLinks: [
    {
      title: '',
      url: '',
    },
  ],
  tags: [],
  privacy: 'Public',
  completionPercentage: 0,
  repository: '',
  deploymentURL: '',
  toolsUsed: [
    {
      category: '',
      name: '',
      description: '',
      proficiency: '',
      version: '',
      documentationLink: '',
    },
  ],
  collaborators: [],
  communicationChannels: [
    {
      platform: '',
      link: '',
    },
  ],
  customFields: {
    field1: '',
    field2: 0,
    field3: false,
  },
  main_image: {
    fileName: '',
    url: '',
  },
  team_role: ''
}


export async function generateMetadata({ params }) {
  return {
    title: " Create Portfolio",
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


const Page = () => {
  return (
    <PrivateLayout>

      <ProjectForm initialValues={initialValue} />

    </PrivateLayout>
  )
}

export default Page