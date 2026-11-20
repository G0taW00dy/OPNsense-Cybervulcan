# JNI entry points in libcvwg.so are looked up by class and method name
# (Java_au_cybervulcan_opnsense_CvNative_*): keep them unrenamed.
-keep class au.cybervulcan.opnsense.CvNative { *; }
