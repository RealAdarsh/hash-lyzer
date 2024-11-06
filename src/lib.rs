pub mod error;

use libxml::tree::{Document, Node};
use xmlsec::{XmlSecNodeSet, XmlSecTransform, XmlSecTransformCtx};
use crate::error::Error;

pub fn create_node_hash(doc: &Document, node: &Node) -> Result<String, Error> {
    let node_set = XmlSecNodeSet::get_children(doc, node, false, false);

    let mut trans_ctx = XmlSecTransformCtx::new();
    let trans = XmlSecTransform::new(xmlsec::XmlSecCanonicalizationMethod::InclusiveC14N);
    trans_ctx.append(trans);
    let trans = XmlSecTransform::with_operation(
        xmlsec::XmlSecCanonicalizationMethod::Sha1,
        xmlsec::XmlSecTransformOperation::Sign,
    );
    trans_ctx.append(trans);
    let trans = XmlSecTransform::with_operation(
        xmlsec::XmlSecCanonicalizationMethod::Base64,
        xmlsec::XmlSecTransformOperation::Encode,
    );
    trans_ctx.append(trans);
    let data = trans_ctx.xml_execute(&node_set)?;
    let base64_data = std::str::from_utf8(data).map_err(|_| Error::HashCreationError)?;

    Ok(String::from(base64_data))
}


#[cfg(test)]
mod test {
    use std::fs;
    use libxml::parser::Parser;
    use libxml::tree::{Document, Namespace, Node};
    use crate::create_node_hash;

    #[test]
    fn test_create_node_hash() {
        let mut doc = Document::new().unwrap();
        let mut root = Node::new("LogReport", None, &doc).unwrap();
        let ns = Namespace::new(
            "lr",
            "http://www.smpte-ra.org/schemas/430-4/2008/LogRecord/",
            &mut root,
        )
            .unwrap();
        Namespace::new(
            "dcml",
            "http://www.smpte-ra.org/schemas/433/2008/dcmlTypes/",
            &mut root,
        )
            .unwrap();
        Namespace::new("ds", "http://www.w3.org/2000/09/xmldsig#", &mut root).unwrap();
        Namespace::new("xs", "http://www.w3.org/2001/XMLSchema", &mut root).unwrap();
        Namespace::new(
            "xsi",
            "http://www.w3.org/2001/XMLSchema-instance",
            &mut root,
        )
            .unwrap();
        root.set_namespace(&ns).unwrap();
        doc.set_root_element(&root);

        let mut node = Node::new("LogRecordBody", Some(ns.clone()), &doc).unwrap();
        root.add_child(&mut node).unwrap();
        let mut eventid = Node::new("EventID", Some(ns.clone()), &doc).unwrap();
        eventid
            .set_content("urn:uuid:1f9d3a08-edd6-4402-99c0-b80d9c7614fc")
            .unwrap();
        node.add_child(&mut eventid).unwrap();
        let mut eventsubtype = Node::new("EventSubType", Some(ns), &doc).unwrap();
        eventsubtype
            .set_attribute(
                "scope",
                "http://www.smpte-ra.org/430-5/2008/SecurityLog/#EventSubTypes-operations",
            )
            .unwrap();
        eventsubtype.set_content("SPBStartup").unwrap();
        node.add_child(&mut eventsubtype).unwrap();

        let data = create_node_hash(&doc, &node).unwrap();

        assert_eq!(data, "0HwjYW3B/l79oq2NHVctyN7qMhE=");
    }

    // #[test]
    // fn test_create_node_hash2() {
    //     let mut doc = Document::new().unwrap();
    //     let mut root = Node::new("LogReport", None, &doc).unwrap();
    //     let ns = Namespace::new(
    //         "lr",
    //         "http://www.smpte-ra.org/schemas/430-4/2008/LogRecord/",
    //         &mut root,
    //     )
    //         .unwrap();
    //     let dcml = Namespace::new(
    //         "dcml",
    //         "http://www.smpte-ra.org/schemas/433/2008/dcmlTypes/",
    //         &mut root,
    //     )
    //         .unwrap();
    //     Namespace::new("ds", "http://www.w3.org/2000/09/xmldsig#", &mut root).unwrap();
    //     Namespace::new("xs", "http://www.w3.org/2001/XMLSchema", &mut root).unwrap();
    //     Namespace::new(
    //         "xsi",
    //         "http://www.w3.org/2001/XMLSchema-instance",
    //         &mut root,
    //     )
    //         .unwrap();
    //     root.set_namespace(&ns).unwrap();
    //     doc.set_root_element(&root);
    //
    //     let mut node = Node::new("LogRecordBody", Some(ns.clone()), &doc).unwrap();
    //     root.add_child(&mut node).unwrap();
    //     let mut eventid = Node::new("EventID", Some(ns.clone()), &doc).unwrap();
    //     eventid
    //         .set_content("urn:uuid:4a42bb5b-3b72-59d1-9035-50c7bd3595ef")
    //         .unwrap();
    //     node.add_child(&mut eventid).unwrap();
    //     let mut eventsubtype = Node::new("EventSubType", Some(ns.clone()), &doc).unwrap();
    //     eventsubtype
    //         .set_attribute(
    //             "scope",
    //             "http://www.smpte-ra.org/430-5/2008/SecurityLog/#EventSubTypes-validation",
    //         )
    //         .unwrap();
    //     eventsubtype.set_content("CPLCheck").unwrap();
    //     node.add_child(&mut eventsubtype).unwrap();
    //
    //     let mut parameters = Node::new("Parameters", Some(ns.clone()), &doc).unwrap();
    //     let mut parameter = Node::new("Parameter", Some(dcml.clone()), &doc).unwrap();
    //     let mut name = Node::new("Name", Some(dcml.clone()), &doc).unwrap();
    //     name.set_content("SignerID").unwrap();
    //     let mut value = Node::new("Value", Some(dcml.clone()), &doc).unwrap();
    //     value.set_content("urn:uuid:4a42bb5b-3b72-59d1-9035-50c7bd3595ef").unwrap();
    //     value.set
    //
    //     let data = create_node_hash(&doc, &node).unwrap();
    //
    //     assert_eq!(data, "0HwjYW3B/l79oq2NHVctyN7qMhE=");
    // }

    #[test]
    fn test_hash_log_record_nodes() {
        // Read the XML file
        let xml_content = fs::read_to_string("/Users/adarsh/Downloads/test_file2").expect("Unable to read file");

        // Parse the XML document
        let parser = Parser::default();
        let doc = parser.parse_string(&xml_content).expect("Unable to parse XML");

        let root = doc.get_root_element().expect("Root element not found");


        for child in root.get_child_nodes(){
            if child.get_name()== "LogRecordElement"{
                let grand_children = child.get_child_nodes();
                for mut grand_child in grand_children{
                    if grand_child.get_name() == "LogRecordHeader"{
                        let hash = create_node_hash(&doc, &grand_child).expect("Unable to create hash");
                        println!("LogRecordHeader hash: {}", hash);
                    }
                    if grand_child.get_name() == "LogRecordBody"{
                        let hash = create_node_hash(&doc, &grand_child).expect("Unable to create hash");
                        println!("LogRecordBody hash: {}", hash);
                    }
                }
            }
        }
    }


}