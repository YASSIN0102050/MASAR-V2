// ══════════════════════════════════════════════════════════
//  MASAR — Courses Database v3
//  رود ماب كاملة + كورسات حقيقية من يوتيوب
// ══════════════════════════════════════════════════════════

var COURSES = {

  // ════════════════════════════════
  //  تطوير المواقع
  // ════════════════════════════════
  webdev: {
    frontend: [
      {id:'fe-1', order:1, title:'HTML5 من الصفر للاحتراف', instructor:'Elzero Web School', level:'b', duration:'6 ساعة', videos:'56 فيديو', ytId:'6QAELgirvjs', ytList:'PLDoPjvoNmBAw_t_XWUFbBX-c9MafPk9ji', desc:'تعلم بناء صفحات الويب بـ HTML5'},
      {id:'fe-2', order:2, title:'CSS3 من الصفر للاحتراف', instructor:'Elzero Web School', level:'b', duration:'13 ساعة', videos:'89 فيديو', ytId:'X1ulCwyhCVM', ytList:'PLDoPjvoNmBAzjsz06gkzlSrlev53MGIKe', desc:'تصميم صفحات احترافية بـ CSS3'},
      {id:'fe-3', order:3, title:'Bootstrap 5 بالعربي', instructor:'Elzero Web School', level:'b', duration:'4 ساعة', videos:'31 فيديو', ytId:'7fddet9ky8s', ytList:'PLDoPjvoNmBAxd9NPEtU5sGJhSw2aWymqJ', desc:'مواقع Responsive بـ Bootstrap'},
      {id:'fe-t1', order:4, title:'مشروع Template HTML & CSS 1', instructor:'Elzero Web School', level:'b', duration:'5 ساعة', videos:'28 فيديو', ytId:'4OGWPn-Q__I', ytList:'PLDoPjvoNmBAyGaRGzPVZCkYx5L7Mo9Tbh', desc:'مشروع تطبيقي: Template كامل'},
      {id:'fe-t2', order:5, title:'مشروع Template HTML & CSS 3', instructor:'Elzero Web School', level:'b', duration:'6 ساعة', videos:'33 فيديو', ytId:'lXVP3rDH9EU', ytList:'PLDoPjvoNmBAxuCSp2_-9LurPqRVwketnc', desc:'مشروع ثاني لتعزيز HTML وCSS'},
      {id:'fe-4', order:6, title:'JavaScript من الصفر للاحتراف', instructor:'Elzero Web School', level:'m', duration:'21 ساعة', videos:'195 فيديو', ytId:'GM6dQBmc-Xg', ytList:'PLDoPjvoNmBAx3kiplQR_oeDqLDBUDYwVv', desc:'أقوى كورس JavaScript عربي'},
      {id:'fe-5', order:7, title:'Git and GitHub بالعربي', instructor:'Elzero Web School', level:'m', duration:'3 ساعة', videos:'32 فيديو', ytId:'ACOiGZoqC8w', ytList:'PLDoPjvoNmBAw4eOj58MZPakHjaO3frVMF', desc:'تحكم في كودك مع Git'},
      {id:'fe-6', order:8, title:'SASS بالعربي كامل', instructor:'Elzero Web School', level:'m', duration:'5 ساعة', videos:'34 فيديو', ytId:'Di_RlcpkpN4', ytList:'PLDoPjvoNmBAz9sluuyOWPifXwww2LNuR', desc:'CSS Preprocessor لكود أنظف'},
      {id:'fe-7', order:9, title:'TypeScript بالعربي كامل', instructor:'Elzero Web School', level:'m', duration:'6 ساعة', videos:'49 فيديو', ytId:'yUndnE-2osg', ytList:'PLDoPjvoNmBAy532K9M_fjiAmrJ0gkCyLx', desc:'أضف TypeScript لمشاريعك'},
      {id:'fe-8', order:10, title:'ReactJS الكورس الكامل', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'38 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'ابنِ تطبيقات ويب بـ React'},
      {id:'fe-9', order:11, title:'jQuery بالعربي كامل', instructor:'Elzero Web School', level:'m', duration:'7 ساعة', videos:'38 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'DOM manipulation بـ jQuery'},
      {id:'fe-10', order:12, title:'مشروع Template HTML & CSS 4', instructor:'Elzero Web School', level:'p', duration:'8 ساعة', videos:'40 فيديو', ytId:'lXVP3rDH9EU', ytList:'PLDoPjvoNmBAy1l-2A21ng3gxEyocruT0t', desc:'مشروع متقدم Frontend'},
    ],
    backend: [
      {id:'be-1', order:1, title:'PHP للمبتدئين بالعربي', instructor:'Elzero Web School', level:'b', duration:'9 ساعة', videos:'60 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAwbgUL56XWTMr9pUFUfIKkP', desc:'Backend بـ PHP من الصفر'},
      {id:'be-2', order:2, title:'MySQL بالعربي من الصفر', instructor:'Elzero Web School', level:'b', duration:'7 ساعة', videos:'40 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAxdiBh6J62wOzEnvC4CNuFU', desc:'قواعد البيانات مع MySQL'},
      {id:'be-3', order:3, title:'Laravel PHP Framework', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'48 فيديو', ytId:'XDuWyYxksXU', ytList:'PLDoPjvoNmBAwy-rS6WKudwVeb_x63EzgS', desc:'أقوى PHP Framework'},
      {id:'be-4', order:4, title:'Node.js بالعربي', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'44 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAwbgUL56XWTMr9pUFUfIKkP', desc:'Backend بـ JavaScript'},
      {id:'be-5', order:5, title:'مشروع eCommerce PHP & MySQL', instructor:'Elzero Web School', level:'p', duration:'15 ساعة', videos:'70 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAxdiBh6J62wOzEnvC4CNuFU', desc:'متجر إلكتروني كامل'},
    ],
    fullstack: [
      {id:'fs-1', order:1, title:'HTML & CSS Template 2', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'40 فيديو', ytId:'lXVP3rDH9EU', ytList:'PLDoPjvoNmBAy1l-2A21ng3gxEyocruT0t', desc:'مشروع متقدم HTML وCSS'},
      {id:'fs-2', order:2, title:'مشروع Full Stack eCommerce', instructor:'Elzero Web School', level:'p', duration:'20 ساعة', videos:'80 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAxdiBh6J62wOzEnvC4CNuFU', desc:'مشروع متكامل Frontend + Backend'},
      {id:'fs-3', order:3, title:'CSS Art Projects', instructor:'Elzero Web School', level:'p', duration:'4 ساعة', videos:'20 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'مشاريع إبداعية بـ CSS'},
    ]
  },

  // ════════════════════════════════
  //  البرمجة
  // ════════════════════════════════
  programming: {
    basics: [
      {id:'pr-b-1', order:1, title:'ما قبل تعلم البرمجة', instructor:'Elzero Web School', level:'b', duration:'2 ساعة', videos:'12 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'أساسيات لازم تعرفها قبل البرمجة'},
      {id:'pr-b-2', order:2, title:'أساسيات البرمجة بـ C++', instructor:'Elzero Web School', level:'b', duration:'8 ساعة', videos:'48 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwy-rS6WKudwVeb_x63EzgS', desc:'مفاهيم البرمجة الأساسية'},
      {id:'pr-b-3', order:3, title:'C++ من الصفر للاحتراف', instructor:'Elzero Web School', level:'b', duration:'18 ساعة', videos:'96 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwy9zquyrSXjlGi37f93Frs', desc:'أشمل كورس C++ بالعربي'},
      {id:'pr-b-4', order:4, title:'حل مسائل Level 1', instructor:'Elzero Web School', level:'b', duration:'5 ساعة', videos:'30 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwgefuRqj8OB5ioMT1eC_EZ', desc:'Problem Solving للمبتدئين'},
    ],
    python: [
      {id:'py-1', order:1, title:'Python من الصفر للاحتراف', instructor:'Elzero Web School', level:'b', duration:'14 ساعة', videos:'125 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'أشهر كورس Python عربي مجاني'},
      {id:'py-2', order:2, title:'Python OOP بالعربي', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'45 فيديو', ytId:'eTwNcqtPcHE', ytList:'PLDoPjvoNmBAy5h_HkGzmgbPzV0Ur3Sk9f', desc:'البرمجة كائنية التوجه بـ Python'},
      {id:'py-3', order:3, title:'Python للأتمتة', instructor:'Elzero Web School', level:'m', duration:'6 ساعة', videos:'28 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'أتمتة المهام بـ Python'},
      {id:'py-4', order:4, title:'Django للمبتدئين', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'60 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'مواقع ويب بـ Python و Django'},
      {id:'py-5', order:5, title:'مشاريع Python متقدمة', instructor:'Elzero Web School', level:'p', duration:'11 ساعة', videos:'50 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'مشاريع Python احترافية'},
    ],
    cpp: [
      {id:'cpp-1', order:1, title:'C من الصفر بالعربي', instructor:'Elzero Web School', level:'b', duration:'6 ساعة', videos:'35 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwy-rS6WKudwVeb_x63EzgS', desc:'لغة C للمبتدئين'},
      {id:'cpp-2', order:2, title:'C++ من الصفر للاحتراف', instructor:'Elzero Web School', level:'b', duration:'18 ساعة', videos:'96 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwy9zquyrSXjlGi37f93Frs', desc:'C++ كامل من الصفر'},
      {id:'cpp-3', order:3, title:'OOP بـ C++ بالعربي', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'52 فيديو', ytId:'eTwNcqtPcHE', ytList:'PLDoPjvoNmBAy5h_HkGzmgbPzV0Ur3Sk9f', desc:'Object Oriented Programming بـ C++'},
      {id:'cpp-4', order:4, title:'C++ حل مسائل Level 2', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'40 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwgefuRqj8OB5ioMT1eC_EZ', desc:'Problem Solving بـ C++'},
      {id:'cpp-5', order:5, title:'C++ مشاريع متقدمة', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'45 فيديو', ytId:'Gkp0xQGOTgE', ytList:'PLDoPjvoNmBAwy9zquyrSXjlGi37f93Frs', desc:'مشاريع C++ احترافية'},
    ],
    java: [
      {id:'java-1', order:1, title:'Java للمبتدئين بالعربي', instructor:'Adel Nasim', level:'b', duration:'12 ساعة', videos:'65 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2Aaje_BDeLKJ9rE7cGoHWPVpn', desc:'ابدأ Java من الصفر'},
      {id:'java-2', order:2, title:'OOP بـ Java بالعربي', instructor:'Adel Nasim', level:'m', duration:'8 ساعة', videos:'40 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2AajqOUW_2SwjWeMwf4vL4RSp', desc:'البرمجة الكائنية بـ Java'},
      {id:'java-3', order:3, title:'Java Collections', instructor:'Adel Nasim', level:'m', duration:'6 ساعة', videos:'30 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2Aaje_BDeLKJ9rE7cGoHWPVpn', desc:'Java Collections Framework'},
      {id:'java-4', order:4, title:'Spring Boot بالعربي', instructor:'Adel Nasim', level:'p', duration:'14 ساعة', videos:'60 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2Aaje_BDeLKJ9rE7cGoHWPVpn', desc:'Backend احترافي بـ Spring Boot'},
    ],
    algorithms: [
      {id:'algo-1', order:1, title:'هياكل البيانات بالعربي C++', instructor:'Adel Nasim', level:'m', duration:'16 ساعة', videos:'74 فيديو', ytId:'owCqVRbZlbg', ytList:'PLCInYL3l2AajqOUW_2SwjWeMwf4vL4RSp', desc:'Data Structures كاملة'},
      {id:'algo-2', order:2, title:'الخوارزميات وتحليل التعقيد', instructor:'Adel Nasim', level:'m', duration:'10 ساعة', videos:'48 فيديو', ytId:'BMUiFMZr7vk', ytList:'PLCInYL3l2AajpF8OH9O2yVkGKCxX0MSNF', desc:'Algorithms وBig O Notation'},
      {id:'algo-3', order:3, title:'خوارزميات الترتيب', instructor:'Adel Nasim', level:'m', duration:'4 ساعة', videos:'20 فيديو', ytId:'BMUiFMZr7vk', ytList:'PLCInYL3l2AajpF8OH9O2yVkGKCxX0MSNF', desc:'Sorting Algorithms بالتفصيل'},
      {id:'algo-4', order:4, title:'Design Patterns بالعربي', instructor:'Adel Nasim', level:'p', duration:'8 ساعة', videos:'36 فيديو', ytId:'BMUiFMZr7vk', ytList:'PLCInYL3l2AajpF8OH9O2yVkGKCxX0MSNF', desc:'Design Patterns OOP'},
      {id:'algo-5', order:5, title:'Competitive Programming', instructor:'Adel Nasim', level:'p', duration:'12 ساعة', videos:'55 فيديو', ytId:'BMUiFMZr7vk', ytList:'PLCInYL3l2AajpF8OH9O2yVkGKCxX0MSNF', desc:'مسابقات البرمجة بالعربي'},
    ]
  },

  // ════════════════════════════════
  //  الذكاء الاصطناعي
  // ════════════════════════════════
  ai: {
    ml: [
      {id:'ml-1', order:1, title:'Python للذكاء الاصطناعي', instructor:'Elzero Web School', level:'b', duration:'8 ساعة', videos:'41 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'Numpy وPandas وMatplotlib'},
      {id:'ml-2', order:2, title:'مقدمة في Machine Learning', instructor:'Elzero Web School', level:'b', duration:'5 ساعة', videos:'22 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'أول خطوة في عالم ML'},
      {id:'ml-3', order:3, title:'Machine Learning كامل بالعربي', instructor:'Elzero Web School', level:'m', duration:'18 ساعة', videos:'78 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'Machine Learning من الصفر'},
      {id:'ml-4', order:4, title:'Scikit-Learn بالتفصيل', instructor:'Elzero Web School', level:'m', duration:'9 ساعة', videos:'38 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'ML Models مع Scikit-Learn'},
    ],
    dl: [
      {id:'dl-1', order:1, title:'Deep Learning المقدمة', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'45 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'شبكات عصبية من الصفر'},
      {id:'dl-2', order:2, title:'Neural Networks بالعربي', instructor:'Elzero Web School', level:'m', duration:'12 ساعة', videos:'55 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'بناء شبكات عصبية'},
      {id:'dl-3', order:3, title:'TensorFlow & Keras كامل', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'42 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'بناء نماذج AI بـ TensorFlow'},
    ],
    cv: [
      {id:'cv-1', order:1, title:'OpenCV Python بالعربي', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'35 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'معالجة الصور بـ OpenCV'},
      {id:'cv-2', order:2, title:'Computer Vision Deep Learning', instructor:'Elzero Web School', level:'p', duration:'12 ساعة', videos:'50 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'CV مع Deep Learning'},
    ],
    nlp: [
      {id:'nlp-1', order:1, title:'NLP مع Python بالعربي', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'42 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'معالجة اللغة الطبيعية'},
      {id:'nlp-2', order:2, title:'Transformers & BERT', instructor:'Elzero Web School', level:'p', duration:'14 ساعة', videos:'58 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'Transformers وHugging Face'},
    ]
  },

  // ════════════════════════════════
  //  تطوير التطبيقات
  // ════════════════════════════════
  apps: {
    flutter: [
      {id:'fl-1', order:1, title:'Dart من الصفر بالعربي', instructor:'Elzero Web School', level:'b', duration:'7 ساعة', videos:'35 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'تعلم Dart قبل Flutter'},
      {id:'fl-2', order:2, title:'Flutter للمبتدئين كامل', instructor:'Elzero Web School', level:'b', duration:'12 ساعة', videos:'56 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'iOS وAndroid بـ Flutter'},
      {id:'fl-3', order:3, title:'Flutter State Management', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'36 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'إدارة الحالة في Flutter'},
      {id:'fl-4', order:4, title:'Flutter + Firebase', instructor:'Elzero Web School', level:'m', duration:'15 ساعة', videos:'70 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAy7YUOBE_H6LNMJuHGtrhlk', desc:'ربط تطبيقك بـ Firebase'},
      {id:'fl-5', order:5, title:'مشروع Flutter كامل', instructor:'Elzero Web School', level:'p', duration:'20 ساعة', videos:'85 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'تطبيق احترافي كامل'},
    ],
    android: [
      {id:'and-1', order:1, title:'Kotlin من الصفر', instructor:'Adel Nasim', level:'b', duration:'8 ساعة', videos:'36 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2AajFAiw4s1U4QbGszcQ-rAb3', desc:'Kotlin لتطوير Android'},
      {id:'and-2', order:2, title:'Android Basics بالعربي', instructor:'Adel Nasim', level:'b', duration:'10 ساعة', videos:'50 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2AajFAiw4s1U4QbGszcQ-rAb3', desc:'أساسيات Android Development'},
      {id:'and-3', order:3, title:'Android Intermediate', instructor:'Adel Nasim', level:'m', duration:'16 ساعة', videos:'72 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2AajFAiw4s1U4QbGszcQ-rAb3', desc:'Android المستوى المتوسط'},
      {id:'and-4', order:4, title:'Jetpack Compose بالعربي', instructor:'Adel Nasim', level:'p', duration:'12 ساعة', videos:'55 فيديو', ytId:'Z4aMegCPVRw', ytList:'PLCInYL3l2AajFAiw4s1U4QbGszcQ-rAb3', desc:'Modern Android UI'},
    ],
    reactnative: [
      {id:'rn-1', order:1, title:'React Native للمبتدئين', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'45 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'تطبيقات Cross-Platform'},
      {id:'rn-2', order:2, title:'React Native كامل', instructor:'Elzero Web School', level:'m', duration:'18 ساعة', videos:'75 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'React Native للمتوسطين'},
      {id:'rn-3', order:3, title:'React Native + Firebase', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'40 فيديو', ytId:'GNrdg3PZcdE', ytList:'PLDoPjvoNmBAzm4gPQMDPKcyMkbKr4L7Bm', desc:'تطبيق React Native كامل'},
    ]
  },

  // ════════════════════════════════
  //  الجرافيك ديزاين
  // ════════════════════════════════
  design: {
    all: [
      {id:'ds-1', order:1, title:'Photoshop للمبتدئين', instructor:'Mahmoud Khafagy', level:'b', duration:'10 ساعة', videos:'45 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Photoshop من الصفر'},
      {id:'ds-2', order:2, title:'Illustrator من الصفر', instructor:'Mahmoud Khafagy', level:'b', duration:'9 ساعة', videos:'40 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Illustrator للمبتدئين'},
      {id:'ds-3', order:3, title:'نظرية الألوان والتصميم', instructor:'Hashem Almehmadi', level:'b', duration:'4 ساعة', videos:'18 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'أساسيات نظرية الألوان'},
      {id:'ds-4', order:4, title:'Figma UI Design كامل', instructor:'Amr Elhelw', level:'m', duration:'14 ساعة', videos:'60 فيديو', ytId:'xiyDNje5BEo', ytList:'PLfDx4Bzkr7nFgz9lMJQ1RpQGGW1JDXvYN', desc:'UI Design بـ Figma'},
      {id:'ds-5', order:5, title:'تصميم الـ Logo', instructor:'Mahmoud Khafagy', level:'m', duration:'7 ساعة', videos:'28 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Logo Design احترافي'},
      {id:'ds-6', order:6, title:'الهوية البصرية', instructor:'Mahmoud Khafagy', level:'m', duration:'12 ساعة', videos:'50 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Brand Identity كاملة'},
      {id:'ds-7', order:7, title:'After Effects من الصفر', instructor:'Hashem Almehmadi', level:'p', duration:'12 ساعة', videos:'52 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'After Effects للمصممين'},
      {id:'ds-8', order:8, title:'Motion Graphics بالعربي', instructor:'Hashem Almehmadi', level:'p', duration:'15 ساعة', videos:'62 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Motion Design احترافي'},
    ]
  },

  // ════════════════════════════════
  //  التسويق الرقمي
  // ════════════════════════════════
  marketing: {
    all: [
      {id:'mk-1', order:1, title:'التسويق الرقمي للمبتدئين', instructor:'Ahmad Taha', level:'b', duration:'6 ساعة', videos:'28 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'أساسيات التسويق الرقمي'},
      {id:'mk-2', order:2, title:'Social Media Marketing', instructor:'Ahmad Taha', level:'b', duration:'5 ساعة', videos:'22 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'تسويق السوشيال ميديا'},
      {id:'mk-3', order:3, title:'Facebook & Instagram Ads', instructor:'Ahmad Taha', level:'m', duration:'12 ساعة', videos:'50 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'إعلانات فيسبوك كاملة'},
      {id:'mk-4', order:4, title:'SEO تحسين محركات البحث', instructor:'Hisham Sarhan', level:'m', duration:'10 ساعة', videos:'45 فيديو', ytId:'r03fOkP_KnQ', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'إتقان SEO'},
      {id:'mk-5', order:5, title:'Google Ads PPC', instructor:'Ahmad Taha', level:'m', duration:'9 ساعة', videos:'38 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'Google Ads احترافي'},
      {id:'mk-6', order:6, title:'Email Marketing', instructor:'Ahmad Taha', level:'m', duration:'5 ساعة', videos:'22 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'Email Marketing كامل'},
      {id:'mk-7', order:7, title:'استراتيجية تسويق متكاملة', instructor:'Ahmad Taha', level:'p', duration:'14 ساعة', videos:'55 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'استراتيجية تسويق شاملة'},
    ]
  },

  // ════════════════════════════════
  //  تحليل البيانات
  // ════════════════════════════════
  data: {
    all: [
      {id:'da-1', order:1, title:'Excel للتحليل من الصفر', instructor:'Elzero Web School', level:'b', duration:'9 ساعة', videos:'42 فيديو', ytId:'V2MkXtHaFKw', ytList:'PLDoPjvoNmBAzjsz06gkzlSrlev53MGIKe', desc:'Excel للمحللين'},
      {id:'da-2', order:2, title:'SQL بالعربي كامل', instructor:'Elzero Web School', level:'b', duration:'8 ساعة', videos:'38 فيديو', ytId:'xcg9qq6SZ0w', ytList:'PLDoPjvoNmBAxdiBh6J62wOzEnvC4CNuFU', desc:'قواعد البيانات بـ SQL'},
      {id:'da-3', order:3, title:'Python للبيانات Pandas', instructor:'Elzero Web School', level:'m', duration:'10 ساعة', videos:'48 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'Pandas وNumPy للتحليل'},
      {id:'da-4', order:4, title:'Data Visualization بالعربي', instructor:'Elzero Web School', level:'m', duration:'7 ساعة', videos:'32 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'رسم البيانات بـ Matplotlib'},
      {id:'da-5', order:5, title:'Power BI كامل', instructor:'Elzero Web School', level:'m', duration:'14 ساعة', videos:'60 فيديو', ytId:'V2MkXtHaFKw', ytList:'PLDoPjvoNmBAzjsz06gkzlSrlev53MGIKe', desc:'داشبورد تحليلية بـ Power BI'},
      {id:'da-6', order:6, title:'مشاريع تحليل بيانات', instructor:'Elzero Web School', level:'p', duration:'18 ساعة', videos:'70 فيديو', ytId:'mvZHDpCHphk', ytList:'PLDoPjvoNmBAyE_gei5d18qkfIe-Z8mocs', desc:'مشاريع تحليل حقيقية'},
    ]
  },

  // ════════════════════════════════
  //  إنتاج الفيديو
  // ════════════════════════════════
  video: {
    all: [
      {id:'vi-1', order:1, title:'أساسيات إنتاج الفيديو', instructor:'Hashem Almehmadi', level:'b', duration:'4 ساعة', videos:'18 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'مقدمة في إنتاج الفيديو'},
      {id:'vi-2', order:2, title:'Premiere Pro للمبتدئين', instructor:'Hashem Almehmadi', level:'b', duration:'8 ساعة', videos:'35 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'المونتاج بـ Premiere Pro'},
      {id:'vi-3', order:3, title:'After Effects من الصفر', instructor:'Mahmoud Khafagy', level:'m', duration:'12 ساعة', videos:'52 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'After Effects كامل'},
      {id:'vi-4', order:4, title:'Color Grading احترافي', instructor:'Mahmoud Khafagy', level:'m', duration:'7 ساعة', videos:'28 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'تصحيح الألوان احترافياً'},
      {id:'vi-5', order:5, title:'Motion Graphics', instructor:'Hashem Almehmadi', level:'m', duration:'15 ساعة', videos:'62 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'تصميم حركي احترافي'},
      {id:'vi-6', order:6, title:'إنتاج يوتيوب احترافي', instructor:'Hashem Almehmadi', level:'p', duration:'11 ساعة', videos:'44 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'صنع محتوى يوتيوب احترافي'},
    ]
  },

  // ════════════════════════════════
  //  كتابة المحتوى
  // ════════════════════════════════
  content: {
    all: [
      {id:'co-1', order:1, title:'أساسيات كتابة المحتوى', instructor:'Hisham Sarhan', level:'b', duration:'4 ساعة', videos:'18 فيديو', ytId:'r03fOkP_KnQ', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'أسس المحتوى الرقمي'},
      {id:'co-2', order:2, title:'Copywriting الإعلاني', instructor:'Ahmad Taha', level:'m', duration:'8 ساعة', videos:'32 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'كتابة إعلانية مقنعة'},
      {id:'co-3', order:3, title:'كتابة مقالات SEO', instructor:'Hisham Sarhan', level:'m', duration:'7 ساعة', videos:'28 فيديو', ytId:'r03fOkP_KnQ', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'مقالات تتصدر البحث'},
      {id:'co-4', order:4, title:'استراتيجية المحتوى', instructor:'Ahmad Taha', level:'p', duration:'10 ساعة', videos:'40 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'بناء استراتيجية محتوى'},
    ]
  },

  // ════════════════════════════════
  //  التصوير
  // ════════════════════════════════
  photography: {
    all: [
      {id:'ph-1', order:1, title:'أساسيات التصوير', instructor:'Mahmoud Khafagy', level:'b', duration:'5 ساعة', videos:'22 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'التصوير من الصفر'},
      {id:'ph-2', order:2, title:'إعدادات الكاميرا', instructor:'Mahmoud Khafagy', level:'b', duration:'4 ساعة', videos:'18 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'إتقان إعدادات الكاميرا'},
      {id:'ph-3', order:3, title:'Lightroom كامل', instructor:'Hashem Almehmadi', level:'m', duration:'9 ساعة', videos:'38 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'تعديل الصور احترافياً'},
      {id:'ph-4', order:4, title:'تصوير البورتريه', instructor:'Mahmoud Khafagy', level:'m', duration:'8 ساعة', videos:'32 فيديو', ytId:'MsgBPKNDOGE', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'Portrait Photography'},
      {id:'ph-5', order:5, title:'تصوير المنتجات', instructor:'Hashem Almehmadi', level:'p', duration:'10 ساعة', videos:'40 فيديو', ytId:'pMTRnJM0bJs', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'تصوير منتجات للتجارة'},
    ]
  },

  // ════════════════════════════════
  //  ريادة الأعمال
  // ════════════════════════════════
  business: {
    all: [
      {id:'bz-1', order:1, title:'مقدمة في ريادة الأعمال', instructor:'Mustafa Khalil', level:'b', duration:'4 ساعة', videos:'18 فيديو', ytId:'rqXKLIafXVU', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'أساسيات بناء المشاريع'},
      {id:'bz-2', order:2, title:'دراسة الجدوى', instructor:'Mustafa Khalil', level:'b', duration:'5 ساعة', videos:'22 فيديو', ytId:'rqXKLIafXVU', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'تقييم الأفكار التجارية'},
      {id:'bz-3', order:3, title:'خطة العمل Business Plan', instructor:'Mustafa Khalil', level:'m', duration:'7 ساعة', videos:'28 فيديو', ytId:'rqXKLIafXVU', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'كيف تكتب Business Plan'},
      {id:'bz-4', order:4, title:'Pitch Deck للمستثمرين', instructor:'Ahmad Taha', level:'m', duration:'6 ساعة', videos:'24 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'عرض مشروعك للمستثمرين'},
      {id:'bz-5', order:5, title:'التسويق للشركات الناشئة', instructor:'Ahmad Taha', level:'m', duration:'8 ساعة', videos:'34 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'تسويق Startup'},
      {id:'bz-6', order:6, title:'Scaling وتوسيع المشروع', instructor:'Mustafa Khalil', level:'p', duration:'9 ساعة', videos:'36 فيديو', ytId:'rqXKLIafXVU', ytList:'PLmvnhGQeMQFqKIjhkHLNTyJi0BwRQKBOC', desc:'توسيع وتكبير مشروعك'},
    ]
  },

  // ════════════════════════════════
  //  الفريلانس  ← جديد
  // ════════════════════════════════
  freelance: {
    all: [
      {id:'fr-1', order:1, title:'مقدمة في الفريلانس', instructor:'Ahmad Taha', level:'b', duration:'3 ساعة', videos:'15 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'ازاي تبدأ شغل فريلانس'},
      {id:'fr-2', order:2, title:'Upwork من الصفر', instructor:'Ahmad Taha', level:'b', duration:'5 ساعة', videos:'24 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'شغل على Upwork'},
      {id:'fr-3', order:3, title:'بناء Portfolio احترافي', instructor:'Ahmad Taha', level:'m', duration:'4 ساعة', videos:'18 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'Portfolio يجذب العملاء'},
      {id:'fr-4', order:4, title:'كيف تسعّر خدماتك', instructor:'Ahmad Taha', level:'m', duration:'3 ساعة', videos:'14 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'تسعير صحيح لخدماتك'},
      {id:'fr-5', order:5, title:'إدارة العملاء والمشاريع', instructor:'Ahmad Taha', level:'p', duration:'5 ساعة', videos:'22 فيديو', ytId:'lqwmDL0agYc', ytList:'PLLDqFKFHSGFG6N32o_iC_oMJQlB2-Hhgo', desc:'إدارة العلاقة مع العملاء'},
    ]
  },

  // ════════════════════════════════
  //  الأمن السيبراني  ← جديد
  // ════════════════════════════════
  security: {
    basics: [
      {id:'sec-b-1', order:1, title:'مقدمة في الأمن السيبراني', instructor:'Elzero Web School', level:'b', duration:'5 ساعة', videos:'24 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'أساسيات Cybersecurity'},
      {id:'sec-b-2', order:2, title:'Linux للمبتدئين', instructor:'Elzero Web School', level:'b', duration:'8 ساعة', videos:'38 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Linux من الصفر'},
      {id:'sec-b-3', order:3, title:'Networking أساسيات الشبكات', instructor:'Elzero Web School', level:'b', duration:'10 ساعة', videos:'46 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'الشبكات من الصفر'},
    ],
    ethical: [
      {id:'sec-e-1', order:1, title:'Ethical Hacking للمبتدئين', instructor:'Elzero Web School', level:'m', duration:'12 ساعة', videos:'55 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Ethical Hacking كامل'},
      {id:'sec-e-2', order:2, title:'Web Penetration Testing', instructor:'Elzero Web School', level:'m', duration:'15 ساعة', videos:'65 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'اختبار اختراق المواقع'},
      {id:'sec-e-3', order:3, title:'Kali Linux كامل', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'44 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Kali Linux للأمن السيبراني'},
    ]
  },

  // ════════════════════════════════
  //  DevOps  ← جديد
  // ════════════════════════════════
  devops: {
    all: [
      {id:'dv-1', order:1, title:'Linux للمطورين', instructor:'Elzero Web School', level:'b', duration:'8 ساعة', videos:'38 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Linux للمطورين من الصفر'},
      {id:'dv-2', order:2, title:'Git & GitHub المتقدم', instructor:'Elzero Web School', level:'b', duration:'5 ساعة', videos:'28 فيديو', ytId:'ACOiGZoqC8w', ytList:'PLDoPjvoNmBAw4eOj58MZPakHjaO3frVMF', desc:'Git للمطورين المتقدمين'},
      {id:'dv-3', order:3, title:'Docker بالعربي كامل', instructor:'Elzero Web School', level:'m', duration:'8 ساعة', videos:'36 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Docker من الصفر'},
      {id:'dv-4', order:4, title:'CI/CD Pipeline', instructor:'Elzero Web School', level:'m', duration:'7 ساعة', videos:'32 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Continuous Integration'},
      {id:'dv-5', order:5, title:'Kubernetes بالعربي', instructor:'Elzero Web School', level:'p', duration:'10 ساعة', videos:'44 فيديو', ytId:'Os7oZCBNRMI', ytList:'PLDoPjvoNmBAzs7Dd-c0L4RJk9S-YqK_6', desc:'Kubernetes للمحترفين'},
    ]
  }
};

// ─── METADATA ──────────────────────────────────────────
var FIELD_META = {
  webdev:       {title:'تطوير المواقع',      subs:{frontend:'Frontend',backend:'Backend',fullstack:'Full Stack'},                           color:'#0a4d3a,#0a7c5c'},
  programming:  {title:'البرمجة',            subs:{basics:'الأساسيات',python:'Python',cpp:'C++ و C',java:'Java',algorithms:'خوارزميات'},    color:'#1a3a6b,#0056d2'},
  apps:         {title:'تطوير التطبيقات',   subs:{flutter:'Flutter',android:'Android',reactnative:'React Native'},                        color:'#1a4a6b,#2980b9'},
  ai:           {title:'الذكاء الاصطناعي', subs:{ml:'Machine Learning',dl:'Deep Learning',cv:'Computer Vision',nlp:'NLP'},               color:'#3a1a6b,#6b21a8'},
  design:       {title:'الجرافيك ديزاين',   subs:{all:'كل الكورسات'},  color:'#6b1a1a,#c0392b'},
  marketing:    {title:'التسويق الرقمي',    subs:{all:'كل الكورسات'},  color:'#6b3d0a,#b45309'},
  data:         {title:'تحليل البيانات',    subs:{all:'كل الكورسات'},  color:'#0a4a4a,#0a7c7c'},
  video:        {title:'إنتاج الفيديو',     subs:{all:'كل الكورسات'},  color:'#1a1a6b,#2c3e8b'},
  content:      {title:'كتابة المحتوى',     subs:{all:'كل الكورسات'},  color:'#2a4a0a,#4a8a1a'},
  photography:  {title:'التصوير',           subs:{all:'كل الكورسات'},  color:'#3a2a0a,#7a5a1a'},
  business:     {title:'ريادة الأعمال',     subs:{all:'كل الكورسات'},  color:'#1a3a0a,#2d6a0a'},
  freelance:    {title:'الفريلانس',          subs:{all:'كل الكورسات'},  color:'#5a0a4a,#8b1a7a'},
  security:     {title:'الأمن السيبراني',   subs:{basics:'الأساسيات',ethical:'Ethical Hacking'}, color:'#1a0a0a,#c0392b'},
  devops:       {title:'DevOps',             subs:{all:'كل الكورسات'},  color:'#0a2a4a,#0a5a8b'},
};

var LL = {b:'مبتدئ', m:'متوسط', p:'محترف'};
var LC = {b:'level-b', m:'level-m', p:'level-p'};

function getAllCourses() {
  var all = [];
  Object.keys(COURSES).forEach(function(field) {
    Object.keys(COURSES[field]).forEach(function(sub) {
      COURSES[field][sub].forEach(function(c) {
        all.push(Object.assign({}, c, {field:field, sub:sub}));
      });
    });
  });
  return all;
}

function findCourseById(id) {
  var fields = Object.keys(COURSES);
  for (var i=0; i<fields.length; i++) {
    var field = fields[i];
    var subs  = Object.keys(COURSES[field]);
    for (var j=0; j<subs.length; j++) {
      var sub  = subs[j];
      var list = COURSES[field][sub];
      for (var k=0; k<list.length; k++) {
        if (list[k].id === id) return Object.assign({}, list[k], {field:field, sub:sub});
      }
    }
  }
  return null;
}

function getRoadmap(field, sub) {
  var list = COURSES[field] && COURSES[field][sub] ? COURSES[field][sub] : [];
  return list.slice().sort(function(a,b){ return (a.order||99)-(b.order||99); });
}
// ═══════════════════════════════════════════════════════════
//  MASAR — Nav & Sidebar Components
// ═══════════════════════════════════════════════════════════

function renderNav() {
  return '<nav class="topnav">' +
    '<a href="/" class="nav-logo">مَسار</a>' +
    '<div class="nav-search">' +
      '<input type="text" id="nav-search" placeholder="ابحث عن كورس أو مجال...">' +
      '<button id="nav-search-btn">بحث</button>' +
    '</div>' +
    '<div class="nav-end" id="nav-end">' +
      '<a href="/pages/login.html"><button class="btn-outline">تسجيل الدخول</button></a>' +
      '<a href="/pages/login.html?tab=register"><button class="btn-solid">إنشاء حساب</button></a>' +
    '</div>' +
  '</nav>';
}

function renderLoginModal() {
  return '<div class="modal-overlay" id="modal-login">' +
    '<div class="modal">' +
      '<h3>تسجيل الدخول مطلوب</h3>' +
      '<p>سجّل دخول عشان تحفظ الكورس وتتابع تقدمك</p>' +
      '<div class="modal-btns">' +
        '<a href="/pages/login.html"><button class="btn-solid" style="padding:9px 22px">تسجيل الدخول</button></a>' +
        '<button class="btn-outline" onclick="document.getElementById(\'modal-login\').classList.remove(\'open\')" style="padding:9px 22px">لاحقاً</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function renderSidebar(activeKey) {
  var parts  = (activeKey || '').split('-');
  var aField = parts[0];
  var aSub   = parts.slice(1).join('-');

  function sbItem(href, icon, label, count, isActive) {
    var countHtml = count ? '<span class="sb-count">' + count + '</span>' : '';
    return '<a href="' + href + '"><div class="sb-item' + (isActive ? ' active' : '') + '">' +
      icon + label + countHtml +
    '</div></a>';
  }

  function sbParent(key, icon, label, isOpen) {
    return '<div class="sb-parent" data-key="' + key + '">' +
      icon + '<span>' + label + '</span>' +
      '<svg class="sb-arrow" viewBox="0 0 24 24" style="transform:' + (isOpen ? 'rotate(90deg)' : '') + '">' +
        '<path d="M8 5v14l11-7z"/>' +
      '</svg>' +
    '</div>';
  }

  function sbChild(href, label, isActive) {
    return '<a href="' + href + '"><div class="sb-child' + (isActive ? ' active' : '') + '">' + label + '</div></a>';
  }

  var icons = {
    home:        '<svg viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>',
    quiz:        '<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17h-2v-2h2v2zm2.07-7.75l-.9.92C13.45 12.9 13 13.5 13 15h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.26c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .88-.36 1.68-.93 2.25z"/></svg>',
    profile:     '<svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>',
    webdev:      '<svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-5 14H4v-4h11v4zm0-5H4V9h11v4zm5 5h-4V9h4v9z"/></svg>',
    programming: '<svg viewBox="0 0 24 24"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>',
    apps:        '<svg viewBox="0 0 24 24"><path d="M17 1.01L7 1c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-1.99-2-1.99z"/></svg>',
    ai:          '<svg viewBox="0 0 24 24"><path d="M21 10.12h-6.78l2.74-2.82-2.02-1.97L12 9.07l-2.94-3.74-2.02 1.97 2.74 2.82H3v2.01h5.12l-2.16 5.02h2.25l.62-1.48h5.3l.62 1.48h2.25l-2.16-5.02H21v-2.01z"/></svg>',
    design:      '<svg viewBox="0 0 24 24"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9c.83 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-.99 0-.83.67-1.5 1.5-1.5H16c2.76 0 5-2.24 5-5 0-4.42-4.03-8-9-8z"/></svg>',
    marketing:   '<svg viewBox="0 0 24 24"><path d="M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6h-6z"/></svg>',
    data:        '<svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg>',
    video:       '<svg viewBox="0 0 24 24"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>',
    content:     '<svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13z"/></svg>',
    photography: '<svg viewBox="0 0 24 24"><path d="M9 2L7.17 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2h-3.17L15 2H9z"/></svg>',
    business:    '<svg viewBox="0 0 24 24"><path d="M20 6h-2.18c.07-.44.18-.88.18-1.36C18 2.51 16.49 1 14.64 1c-1.18 0-2.13.7-2.82 1.55L12 3.22l-.82-.67C10.49 1.7 9.54 1 8.36 1 6.51 1 5 2.51 5 4.64c0 .48.11.92.18 1.36H3c-1.1 0-2 .9-2 2v11c0 1.1.9 2 2 2h17c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/></svg>',
    groups:      '<svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>',
    freelance:   '<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z"/></svg>',
    security:    '<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>',
    devops:      '<svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>'
  };

  var webdevOpen      = aField === 'webdev';
  var programmingOpen = aField === 'programming';
  var appsOpen        = aField === 'apps';
  var aiOpen          = aField === 'ai';

  var html = '<aside class="sidebar">';

  // Navigation
  html += '<div class="sb-section">';
  html += '<div class="sb-label">التنقل</div>';
  html += sbItem('/', icons.home, 'الرئيسية', '', activeKey === '' || activeKey === 'home');
  html += sbItem('/pages/quiz.html', icons.quiz, 'اكتشف مسارك', '', activeKey === 'quiz');
  html += sbItem('/pages/profile.html', icons.profile, 'حسابي', '', activeKey === 'profile');
  html += '</div>';
  html += '<hr class="sb-divider">';

  // Fields
  html += '<div class="sb-section">';
  html += '<div class="sb-label">المجالات</div>';

  // تطوير المواقع
  html += sbParent('webdev', icons.webdev, 'تطوير المواقع', webdevOpen);
  html += '<div class="sb-children' + (webdevOpen ? ' open' : '') + '" id="sb-ch-webdev">';
  html += sbChild('/pages/field.html?f=webdev&sub=frontend',  'Frontend',   aField === 'webdev' && aSub === 'frontend');
  html += sbChild('/pages/field.html?f=webdev&sub=backend',   'Backend',    aField === 'webdev' && aSub === 'backend');
  html += sbChild('/pages/field.html?f=webdev&sub=fullstack', 'Full Stack', aField === 'webdev' && aSub === 'fullstack');
  html += '</div>';

  // البرمجة
  html += sbParent('programming', icons.programming, 'البرمجة', programmingOpen);
  html += '<div class="sb-children' + (programmingOpen ? ' open' : '') + '" id="sb-ch-programming">';
  html += sbChild('/pages/field.html?f=programming&sub=basics',     'الأساسيات', aField === 'programming' && aSub === 'basics');
  html += sbChild('/pages/field.html?f=programming&sub=python',     'Python',     aField === 'programming' && aSub === 'python');
  html += sbChild('/pages/field.html?f=programming&sub=cpp',        'C++ و C',    aField === 'programming' && aSub === 'cpp');
  html += sbChild('/pages/field.html?f=programming&sub=java',       'Java',       aField === 'programming' && aSub === 'java');
  html += sbChild('/pages/field.html?f=programming&sub=algorithms', 'خوارزميات', aField === 'programming' && aSub === 'algorithms');
  html += '</div>';

  // تطوير التطبيقات
  html += sbParent('apps', icons.apps, 'تطوير التطبيقات', appsOpen);
  html += '<div class="sb-children' + (appsOpen ? ' open' : '') + '" id="sb-ch-apps">';
  html += sbChild('/pages/field.html?f=apps&sub=flutter',      'Flutter',      aField === 'apps' && aSub === 'flutter');
  html += sbChild('/pages/field.html?f=apps&sub=android',      'Android',      aField === 'apps' && aSub === 'android');
  html += sbChild('/pages/field.html?f=apps&sub=reactnative',  'React Native', aField === 'apps' && aSub === 'reactnative');
  html += '</div>';

  // الذكاء الاصطناعي
  html += sbParent('ai', icons.ai, 'الذكاء الاصطناعي', aiOpen);
  html += '<div class="sb-children' + (aiOpen ? ' open' : '') + '" id="sb-ch-ai">';
  html += sbChild('/pages/field.html?f=ai&sub=ml',  'Machine Learning', aField === 'ai' && aSub === 'ml');
  html += sbChild('/pages/field.html?f=ai&sub=dl',  'Deep Learning',    aField === 'ai' && aSub === 'dl');
  html += sbChild('/pages/field.html?f=ai&sub=cv',  'Computer Vision',  aField === 'ai' && aSub === 'cv');
  html += sbChild('/pages/field.html?f=ai&sub=nlp', 'NLP',              aField === 'ai' && aSub === 'nlp');
  html += '</div>';

  // باقي المجالات
  html += sbItem('/pages/field.html?f=design',      icons.design,      'الجرافيك ديزاين', '8',  aField === 'design');
  html += sbItem('/pages/field.html?f=marketing',   icons.marketing,   'التسويق الرقمي',  '7',  aField === 'marketing');
  html += sbItem('/pages/field.html?f=data',        icons.data,        'تحليل البيانات',  '6',  aField === 'data');
  html += sbItem('/pages/field.html?f=video',       icons.video,       'إنتاج الفيديو',   '6',  aField === 'video');
  html += sbItem('/pages/field.html?f=content',     icons.content,     'كتابة المحتوى',   '4',  aField === 'content');
  html += sbItem('/pages/field.html?f=photography', icons.photography, 'التصوير',         '5',  aField === 'photography');
  html += sbItem('/pages/field.html?f=business',    icons.business,    'ريادة الأعمال',   '6',  aField === 'business');
  html += sbItem('/pages/field.html?f=freelance',   icons.freelance,   'الفريلانس',        '5',  aField === 'freelance');

  // الأمن السيبراني — collapsible
  var securityOpen = aField === 'security';
  html += sbParent('security', icons.security, 'الأمن السيبراني', securityOpen);
  html += '<div class="sb-children' + (securityOpen ? ' open' : '') + '" id="sb-ch-security">';
  html += sbChild('/pages/field.html?f=security&sub=basics',  'الأساسيات',      aField === 'security' && aSub === 'basics');
  html += sbChild('/pages/field.html?f=security&sub=ethical', 'Ethical Hacking', aField === 'security' && aSub === 'ethical');
  html += '</div>';

  html += sbItem('/pages/field.html?f=devops', icons.devops, 'DevOps', '5', aField === 'devops');

  html += '</div>';
  html += '<hr class="sb-divider">';

  // Community
  html += '<div class="sb-section">';
  html += '<div class="sb-label">المجتمع</div>';
  html += sbItem('/pages/groups.html', icons.groups, 'الجروبات', '', activeKey === 'groups');
  html += '</div>';

  html += '</aside>';
  return html;
}
// ═══════════════════════════════════════════════════════════
//  MASAR — Shared App Logic
// ═══════════════════════════════════════════════════════════

const API = {
  async req(method, url, body) {
    const opts = { method, credentials: 'include', headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'خطأ في السيرفر');
    return data;
  },
  get:    function(url)      { return API.req('GET',    url); },
  post:   function(url, b)   { return API.req('POST',   url, b); },
  put:    function(url, b)   { return API.req('PUT',    url, b); },
  delete: function(url)      { return API.req('DELETE', url); }
};

var currentUser = null;
var savedSet    = new Set();
var progressMap = {};

async function loadUser() {
  try {
    currentUser = await API.get('/api/auth/me');
  } catch(e) {
    currentUser = null;
  }
  renderNavUser();
  return currentUser;
}

function renderNavUser() {
  var end = document.getElementById('nav-end');
  if (!end) return;
  if (currentUser) {
    var init = currentUser.name.charAt(0).toUpperCase();
    end.innerHTML =
      '<div class="nav-user">' +
        '<div class="nav-avatar">' + init + '</div>' +
        '<span style="font-size:13px;font-weight:600">' + currentUser.name + '</span>' +
      '</div>' +
      '<a href="/pages/profile.html"><button class="btn-outline" style="font-size:12px;padding:5px 12px">حسابي</button></a>' +
      '<button class="btn-outline" style="font-size:12px;padding:5px 12px" onclick="doLogout()">خروج</button>';
  } else {
    end.innerHTML =
      '<a href="/pages/login.html"><button class="btn-outline">تسجيل الدخول</button></a>' +
      '<a href="/pages/login.html?tab=register"><button class="btn-solid">إنشاء حساب</button></a>';
  }
}

async function doLogout() {
  try { await API.post('/api/auth/logout'); } catch(e) {}
  currentUser = null;
  renderNavUser();
  showToast('تم تسجيل الخروج');
  setTimeout(function() { location.href = '/'; }, 1000);
}

async function loadSaved() {
  if (!currentUser) return;
  try {
    var ids = await API.get('/api/saved');
    savedSet = new Set(ids);
  } catch(e) {}
}

async function toggleSave(courseId, btn) {
  if (!currentUser) {
    var m = document.getElementById('modal-login');
    if (m) m.classList.add('open');
    return;
  }
  try {
    var res = await API.post('/api/saved/toggle', { course_id: courseId });
    if (res.saved) {
      savedSet.add(courseId);
      btn.textContent = 'محفوظ';
      btn.classList.add('saved');
    } else {
      savedSet.delete(courseId);
      btn.textContent = 'حفظ';
      btn.classList.remove('saved');
    }
  } catch(e) { showToast(e.message); }
}

async function loadProgress() {
  if (!currentUser) return;
  try {
    var rows = await API.get('/api/progress');
    progressMap = {};
    rows.forEach(function(r) { progressMap[r.course_id] = r; });
  } catch(e) {}
}

function showToast(msg) {
  var t = document.querySelector('.toast');
  if (!t) { t = document.createElement('div'); t.className = 'toast'; document.body.appendChild(t); }
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(function() { t.classList.remove('show'); }, 2500);
}

function initNavSearch() {
  var inp = document.getElementById('nav-search');
  if (!inp) return;
  inp.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      var q = inp.value.trim();
      if (q) location.href = '/pages/field.html?search=' + encodeURIComponent(q);
    }
  });
  var btn = document.getElementById('nav-search-btn');
  if (btn) btn.onclick = function() {
    var q = inp.value.trim();
    if (q) location.href = '/pages/field.html?search=' + encodeURIComponent(q);
  };
}

function initSidebarToggles() {
  document.querySelectorAll('.sb-parent').forEach(function(el) {
    el.addEventListener('click', function() {
      var key = el.dataset.key;
      var children = document.getElementById('sb-ch-' + key);
      var arrow = el.querySelector('.sb-arrow');
      if (!children) return;
      var open = children.classList.toggle('open');
      if (arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
    });
  });
}

document.addEventListener('DOMContentLoaded', async function() {
  await loadUser();
  initNavSearch();
  initSidebarToggles();
  if (currentUser) {
    await Promise.all([loadSaved(), loadProgress()]);
  }
  if (typeof pageInit === 'function') pageInit();
});