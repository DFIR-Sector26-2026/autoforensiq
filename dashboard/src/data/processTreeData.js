const processTreeData = {
  name: "explorer.exe",

  attributes: {
    pid: "1636",
    suspicious: "false",
  },

  children: [

    {
      name: "tasksche.exe",

      attributes: {
        pid: "1940",
        suspicious: "true",
      },

      children: [

        {
          name: "@WanaDecryptor@",

          attributes: {
            pid: "740",
            suspicious: "critical",
          },

          children: [],
        },
      ],
    },
  ],
};

export default processTreeData;
