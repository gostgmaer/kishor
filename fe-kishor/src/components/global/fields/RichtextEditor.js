// RichTextEditor.js
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css'; // import styles

const RichTextEditor = ({ value, onChange }) => {

    const modules = {
        toolbar: [
          [{ 'header': '1'}, {'header': '2'}, { 'font': [] }],
          [{size: []}],
          ['bold', 'italic', 'underline', 'strike', 'blockquote'],
          [{'list': 'ordered'}, {'list': 'bullet'}, 
           {'indent': '-1'}, {'indent': '+1'}],
          ['link', 'image', 'video'],
          ['clean']
        ],
        clipboard: {
          // toggle to add extra line breaks when pasting HTML:
          matchVisual: false,
        }
      }
const  formats = [
    'header',
    'bold', 'italic', 'underline', 'strike',
    'blockquote', 'code-block',
    'list', 'bullet',
    'script', 'indent',
    'size',
    'link', 'image',
  ];

  return (
    <ReactQuill
      theme="snow"
      modules={modules}
      formats={formats}
    
      value={value}
      onChange={onChange}
      className=' min-h-[180px] h-48 rounded-lg mb-16'

    />
  );
};

export default RichTextEditor;
