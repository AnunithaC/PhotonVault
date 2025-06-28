import cv2
import numpy as np

def preprocess_image(path):
    img = cv2.imread(path, 0)  # Grayscale
    if img is None:
        raise ValueError(f"Could not load image from {path}")

    img = cv2.resize(img, (300, 300))
    img = cv2.equalizeHist(img)  # Contrast normalization
    img = cv2.GaussianBlur(img, (5, 5), 0)  # Reduce noise
    return img

def match_images(image1_path, image2_path, threshold=15):
    try:
        img1 = preprocess_image(image1_path)
        img2 = preprocess_image(image2_path)

        orb = cv2.ORB_create()
        kp1, des1 = orb.detectAndCompute(img1, None)
        kp2, des2 = orb.detectAndCompute(img2, None)

        if des1 is None or des2 is None:
            print("Not enough features detected.")
            return False

        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = bf.match(des1, des2)
        good_matches = [m for m in matches if m.distance < 50]

        print(f"Total Matches: {len(matches)} | Good Matches: {len(good_matches)}")

        if len(good_matches) > threshold:
            return True
        return False

    except Exception as e:
        print("Matching error:", e)
        return False

