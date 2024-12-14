export const initialProjectValues = {
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
    tasks: [{
        title: '',
        description: '',
        status: 'Not Started',
    }],
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
    milestones: [{
        title: '',
        description: '',
        dueDate: '',
    }],
    attachments: [{
        fileName: '',
        url: '',
    }],
    notes: '',
    risks: [{
        description: '',
        probability: 0,
        impact: '',
        mitigation: '',
    }],
    feedback: [{
        date: '',
        from: '',
        message: '',
    }],
    projectLinks: [{
        title: '',
        url: '',
    }],
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
    communicationChannels: [{
        platform: '',
        link: '',
    }],
    customFields: {
        field1: '',
        field2: 0,
        field3: false,
    },
};
