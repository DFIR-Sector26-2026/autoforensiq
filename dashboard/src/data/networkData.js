const networkData = {

  nodes: [

    {
      id: "WannaDecryptor",
      group: "malware",
    },

    {
      id: "192.168.1.10",
      group: "internal",
    },

    {
      id: "45.33.32.156",
      group: "external",
    },

    {
      id: "Command Server",
      group: "c2",
    },
  ],

  links: [

    {
      source: "WannaDecryptor",
      target: "192.168.1.10",
    },

    {
      source: "192.168.1.10",
      target: "45.33.32.156",
    },

    {
      source: "45.33.32.156",
      target: "Command Server",
    },
  ],
};

export default networkData;
